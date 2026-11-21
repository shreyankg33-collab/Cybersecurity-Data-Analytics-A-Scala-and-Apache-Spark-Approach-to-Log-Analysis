package com.cybersec

import com.cybersec.analytics.ThreatDetector
import com.cybersec.models.AnalysisSummary
import com.cybersec.parser.LogParser
import com.cybersec.report.ReportExporter
import org.apache.spark.sql.SparkSession

import java.time.Instant
import java.util.Locale

object Main {

  def main(args: Array[String]): Unit = {
    // Ensure English month names (e.g. "Nov") parse reliably regardless of OS locale
    Locale.setDefault(Locale.US)

    val inputPath = args.headOption.getOrElse("data/sample_access.log")
    val jsonOutputPath = if (args.length > 1) args(1) else "dashboard/data/report.json"
    val csvOutputPath = if (args.length > 2) args(2) else "output/threat_alerts.csv"

    val spark = SparkSession.builder()
      .appName("Cybersecurity Log Analytics - Scala & Apache Spark")
      .master("local[*]")
      .config("spark.ui.enabled", "false")
      .config("spark.sql.shuffle.partitions", "4")
      .getOrCreate()

    spark.sparkContext.setLogLevel("WARN")

    try {
      println(s"\n[1/4] Ingesting and parsing logs from: $inputPath ...")
      val (parsedLogs, totalRawLines, malformedLines) = LogParser.parseAccessLogs(spark, inputPath)
      val validCount = parsedLogs.count()
      val uniqueIps = parsedLogs.select("ip").distinct().count()

      println("[2/4] Running Apache Spark threat detection rules ...")
      val alertsDs = ThreatDetector.detectAllThreats(spark, parsedLogs).cache()
      val alerts = alertsDs.collect().toSeq

      println("[3/4] Computing IP risk profiles, traffic timelines, and endpoint metrics ...")
      val topRiskyIps = ThreatDetector.buildIpRiskProfiles(spark, parsedLogs, alertsDs).collect().toSeq
      val timeline = ThreatDetector.buildTimeline(spark, parsedLogs)
      val statusBreakdown = ThreatDetector.buildStatusBreakdown(spark, parsedLogs)
      val topEndpoints = ThreatDetector.buildTopEndpoints(spark, parsedLogs)

      val summary = AnalysisSummary(
        sourceFile = inputPath,
        generatedAt = Instant.now().toString,
        totalRawLines = totalRawLines,
        parsedLogs = validCount,
        malformedLines = malformedLines,
        uniqueIps = uniqueIps,
        totalAlerts = alerts.size.toLong,
        criticalAlerts = alerts.count(_.severity == "CRITICAL").toLong,
        highAlerts = alerts.count(_.severity == "HIGH").toLong,
        mediumAlerts = alerts.count(_.severity == "MEDIUM").toLong,
        alerts = alerts,
        topRiskyIps = topRiskyIps,
        timeline = timeline,
        statusBreakdown = statusBreakdown,
        topEndpoints = topEndpoints
      )

      println("[4/4] Exporting threat reports ...")
      ReportExporter.writeJsonReport(summary, jsonOutputPath)
      ReportExporter.writeAlertsCsv(alerts, csvOutputPath)
      ReportExporter.printConsoleSummary(summary)

      println(s"\nSaved dashboard JSON : $jsonOutputPath")
      println(s"Saved alerts CSV     : $csvOutputPath")
      println("Open dashboard/index.html (via VS Code Live Server or GitHub Pages) to explore visually.\n")

      alertsDs.unpersist()
      parsedLogs.unpersist()
    } finally {
      spark.stop()
    }
  }
}
