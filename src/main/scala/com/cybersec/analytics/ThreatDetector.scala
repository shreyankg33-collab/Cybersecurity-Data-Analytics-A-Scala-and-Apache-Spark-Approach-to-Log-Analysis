package com.cybersec.analytics

import com.cybersec.models._
import org.apache.spark.sql.{Dataset, SparkSession}
import org.apache.spark.sql.functions._

object ThreatDetector {

  private val SqlInjectionRegex =
    "(?i)(union(%20|\\+|\\s)+select|select(%20|\\+|\\s)+.*(%20|\\+|\\s)+from|(%27|')\\s*or\\s*['\"]?1['\"]?\\s*=\\s*['\"]?1|or(%20|\\+|\\s)+1=1|;--|drop(%20|\\+|\\s)+table)"

  private val XssRegex =
    "(?i)(<script|%3cscript|javascript:|onerror=|onload=|alert\\()"

  private val PathTraversalRegex =
    "(?i)(\\.\\./|\\.\\.%2f|%2e%2e%2f|/etc/passwd|/etc/shadow|win\\.ini|boot\\.ini)"

  /**
   * 1. Brute-Force / Credential Stuffing Detection:
   *    Flags IPs with >= 5 unauthorized (401/403) responses inside a 5-minute window.
   */
  def detectBruteForce(spark: SparkSession, logs: Dataset[ParsedLog]): Dataset[ThreatAlert] = {
    import spark.implicits._

    logs
      .filter($"statusCode".isin(401, 403))
      .groupBy($"ip", window($"eventTime", "5 minutes").as("tw"))
      .agg(
        count("*").as("eventCount"),
        date_format(min($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("firstSeen"),
        date_format(max($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("lastSeen"),
        first($"endpoint").as("targetEndpoint")
      )
      .filter($"eventCount" >= 5)
      .select(
        lit("Brute-Force / Auth Abuse").as("alertType"),
        when($"eventCount" >= 15, lit("CRITICAL")).otherwise(lit("HIGH")).as("severity"),
        $"ip",
        $"eventCount",
        $"firstSeen",
        $"lastSeen",
        concat(
          $"eventCount",
          lit(" failed auth attempts (401/403) in 5m targeting "),
          $"targetEndpoint"
        ).as("details")
      )
      .as[ThreatAlert]
  }

  /**
   * 2. DDoS / High-Rate Traffic Spike Detection:
   *    Uses Spark SQL per-minute aggregations and Z-score anomaly detection.
   */
  def detectDdosSpikes(spark: SparkSession, logs: Dataset[ParsedLog]): Dataset[ThreatAlert] = {
    import spark.implicits._

    val perMinute = logs
      .groupBy($"ip", window($"eventTime", "1 minute").as("tw"))
      .agg(
        count("*").as("reqPerMin"),
        date_format(min($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("firstSeen"),
        date_format(max($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("lastSeen")
      )

    val baselineStats = perMinute.agg(
      avg($"reqPerMin").as("meanReq"),
      coalesce(stddev_pop($"reqPerMin"), lit(0.0)).as("stdReq")
    )

    perMinute
      .crossJoin(baselineStats)
      .withColumn(
        "zScore",
        when($"stdReq" > 0.0, ($"reqPerMin" - $"meanReq") / $"stdReq").otherwise(lit(0.0))
      )
      .filter($"reqPerMin" >= 25 || ($"reqPerMin" >= 15 && $"zScore" >= 2.5))
      .select(
        lit("DDoS / Traffic Flood").as("alertType"),
        when($"reqPerMin" >= 40, lit("CRITICAL")).otherwise(lit("HIGH")).as("severity"),
        $"ip",
        $"reqPerMin".as("eventCount"),
        $"firstSeen",
        $"lastSeen",
        concat(
          $"reqPerMin",
          lit(" req/min burst (z-score="),
          round($"zScore", 2),
          lit(")")
        ).as("details")
      )
      .as[ThreatAlert]
  }

  /**
   * 3. Web Application Attack Signature Detection:
   *    Detects SQL Injection, XSS, and Path Traversal payloads in requested URLs.
   */
  def detectWebPayloads(spark: SparkSession, logs: Dataset[ParsedLog]): Dataset[ThreatAlert] = {
    import spark.implicits._

    val tagged = logs
      .withColumn(
        "alertType",
        when($"endpoint".rlike(SqlInjectionRegex), lit("SQL Injection Attempt"))
          .when($"endpoint".rlike(XssRegex), lit("Cross-Site Scripting (XSS)"))
          .when($"endpoint".rlike(PathTraversalRegex), lit("Path Traversal Attempt"))
          .otherwise(lit(null))
      )
      .filter($"alertType".isNotNull)

    tagged
      .groupBy($"ip", $"alertType")
      .agg(
        count("*").as("eventCount"),
        date_format(min($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("firstSeen"),
        date_format(max($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("lastSeen"),
        first($"endpoint").as("samplePayload")
      )
      .select(
        $"alertType",
        when($"alertType" === "SQL Injection Attempt" || $"alertType" === "Path Traversal Attempt", lit("CRITICAL"))
          .otherwise(lit("HIGH"))
          .as("severity"),
        $"ip",
        $"eventCount",
        $"firstSeen",
        $"lastSeen",
        concat(lit("Matched signature on payload: "), substring($"samplePayload", 1, 90)).as("details")
      )
      .as[ThreatAlert]
  }

  /**
   * 4. Directory / Vulnerability Scanning Detection:
   *    Flags IPs generating >= 8 HTTP 404 responses across >= 5 distinct paths within 5 minutes.
   */
  def detectDirectoryScanning(spark: SparkSession, logs: Dataset[ParsedLog]): Dataset[ThreatAlert] = {
    import spark.implicits._

    logs
      .filter($"statusCode" === 404)
      .groupBy($"ip", window($"eventTime", "5 minutes").as("tw"))
      .agg(
        count("*").as("notFoundCount"),
        countDistinct($"endpoint").as("uniquePaths"),
        date_format(min($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("firstSeen"),
        date_format(max($"eventTime"), "yyyy-MM-dd HH:mm:ss").as("lastSeen")
      )
      .filter($"notFoundCount" >= 8 && $"uniquePaths" >= 5)
      .select(
        lit("Directory / Recon Scan").as("alertType"),
        when($"uniquePaths" >= 15, lit("HIGH")).otherwise(lit("MEDIUM")).as("severity"),
        $"ip",
        $"notFoundCount".as("eventCount"),
        $"firstSeen",
        $"lastSeen",
        concat(
          $"notFoundCount",
          lit(" HTTP 404 errors across "),
          $"uniquePaths",
          lit(" distinct paths in 5m")
        ).as("details")
      )
      .as[ThreatAlert]
  }

  /**
   * Runs all threat detectors and unions them into a single prioritized Dataset[ThreatAlert].
   */
  def detectAllThreats(spark: SparkSession, logs: Dataset[ParsedLog]): Dataset[ThreatAlert] = {
    import spark.implicits._

    val combined = detectBruteForce(spark, logs)
      .union(detectDdosSpikes(spark, logs))
      .union(detectWebPayloads(spark, logs))
      .union(detectDirectoryScanning(spark, logs))

    combined
      .withColumn(
        "severityRank",
        when($"severity" === "CRITICAL", 1)
          .when($"severity" === "HIGH", 2)
          .otherwise(3)
      )
      .orderBy($"severityRank".asc, $"eventCount".desc)
      .drop("severityRank")
      .as[ThreatAlert]
  }

  /**
   * Computes per-IP composite risk scores (0 - 100) by joining traffic metrics with detected alerts.
   */
  def buildIpRiskProfiles(
    spark: SparkSession,
    logs: Dataset[ParsedLog],
    alerts: Dataset[ThreatAlert]
  ): Dataset[IpRiskProfile] = {
    import spark.implicits._

    val trafficByIp = logs
      .groupBy($"ip")
      .agg(
        count("*").as("totalRequests"),
        sum(when($"statusCode" >= 400, 1L).otherwise(0L)).as("errorRequests"),
        sum($"bytesSent").as("totalBytes")
      )

    val alertScoreByIp = alerts
      .withColumn(
        "weight",
        when($"severity" === "CRITICAL", 40)
          .when($"severity" === "HIGH", 25)
          .otherwise(12)
      )
      .groupBy($"ip")
      .agg(
        count("*").as("alertCount"),
        sum($"weight").as("rawRiskScore"),
        concat_ws(", ", collect_set($"alertType")).as("attackTypes")
      )

    trafficByIp
      .join(alertScoreByIp, Seq("ip"), "left")
      .select(
        $"ip",
        $"totalRequests",
        $"errorRequests",
        $"totalBytes",
        coalesce($"alertCount", lit(0L)).as("alertCount"),
        least(lit(100), coalesce($"rawRiskScore", lit(0)).cast("int")).as("riskScore"),
        coalesce($"attackTypes", lit("None")).as("attackTypes")
      )
      .withColumn(
        "riskLevel",
        when($"riskScore" >= 70, lit("CRITICAL"))
          .when($"riskScore" >= 40, lit("HIGH"))
          .when($"riskScore" >= 15, lit("MEDIUM"))
          .otherwise(lit("LOW"))
      )
      .select(
        $"ip",
        $"totalRequests",
        $"errorRequests",
        $"totalBytes",
        $"alertCount",
        $"riskScore",
        $"riskLevel",
        $"attackTypes"
      )
      .orderBy($"riskScore".desc, $"totalRequests".desc)
      .limit(15)
      .as[IpRiskProfile]
  }

  def buildTimeline(spark: SparkSession, logs: Dataset[ParsedLog]): Seq[TimelinePoint] = {
    import spark.implicits._

    logs
      .groupBy(date_format($"eventTime", "HH:mm").as("minuteBucket"))
      .agg(
        count("*").as("totalRequests"),
        sum(when($"statusCode" >= 400, 1L).otherwise(0L)).as("errorRequests")
      )
      .orderBy($"minuteBucket".asc)
      .as[TimelinePoint]
      .collect()
      .toSeq
  }

  def buildStatusBreakdown(spark: SparkSession, logs: Dataset[ParsedLog]): Seq[StatusCount] = {
    import spark.implicits._

    logs
      .withColumn(
        "statusGroup",
        when($"statusCode" >= 200 && $"statusCode" < 300, lit("2xx Success"))
          .when($"statusCode" >= 300 && $"statusCode" < 400, lit("3xx Redirect"))
          .when($"statusCode" >= 400 && $"statusCode" < 500, lit("4xx Client Error"))
          .when($"statusCode" >= 500, lit("5xx Server Error"))
          .otherwise(lit("Other"))
      )
      .groupBy($"statusGroup")
      .agg(count("*").as("count"))
      .orderBy($"statusGroup".asc)
      .as[StatusCount]
      .collect()
      .toSeq
  }

  def buildTopEndpoints(spark: SparkSession, logs: Dataset[ParsedLog]): Seq[EndpointMetric] = {
    import spark.implicits._

    logs
      .withColumn("cleanEndpoint", split($"endpoint", "\\?").getItem(0))
      .groupBy($"cleanEndpoint".as("endpoint"))
      .agg(
        count("*").as("hits"),
        sum(when($"statusCode" >= 400, 1L).otherwise(0L)).as("errorHits")
      )
      .orderBy($"hits".desc)
      .limit(10)
      .as[EndpointMetric]
      .collect()
      .toSeq
  }
}
