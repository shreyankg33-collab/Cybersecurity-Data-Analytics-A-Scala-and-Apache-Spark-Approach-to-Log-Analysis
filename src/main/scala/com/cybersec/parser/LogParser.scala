package com.cybersec.parser

import com.cybersec.models.ParsedLog
import org.apache.spark.sql.{Dataset, SparkSession}
import org.apache.spark.sql.functions._

object LogParser {

  // Apache / Nginx Combined Log Format:
  // 192.168.1.10 - - [21/Nov/2026:10:01:15 +0000] "GET /api/login HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
  private val CombinedLogPattern =
    """^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) \S+" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$"""

  /**
   * Parses raw text lines into a typed Spark Dataset[ParsedLog].
   * Returns (parsedLogs, totalRawLines, malformedLines).
   */
  def parseAccessLogs(spark: SparkSession, inputPath: String): (Dataset[ParsedLog], Long, Long) = {
    import spark.implicits._

    val rawDf = spark.read.text(inputPath).cache()
    val totalRawLines = rawDf.count()

    val extractedDf = rawDf
      .select(
        regexp_extract($"value", CombinedLogPattern, 1).as("ip"),
        regexp_extract($"value", CombinedLogPattern, 2).as("rawTimestamp"),
        regexp_extract($"value", CombinedLogPattern, 3).as("method"),
        regexp_extract($"value", CombinedLogPattern, 4).as("endpoint"),
        regexp_extract($"value", CombinedLogPattern, 5).as("rawStatus"),
        regexp_extract($"value", CombinedLogPattern, 6).as("rawBytes"),
        regexp_extract($"value", CombinedLogPattern, 7).as("referrer"),
        regexp_extract($"value", CombinedLogPattern, 8).as("userAgent")
      )

    val parsedDs = extractedDf
      .filter($"ip" =!= "" && $"rawTimestamp" =!= "" && $"rawStatus" =!= "")
      .withColumn("eventTime", to_timestamp($"rawTimestamp", "dd/MMM/yyyy:HH:mm:ss Z"))
      .filter($"eventTime".isNotNull)
      .withColumn("statusCode", $"rawStatus".cast("int"))
      .withColumn(
        "bytesSent",
        when($"rawBytes" === "-" || $"rawBytes" === "", lit(0L))
          .otherwise($"rawBytes".cast("long"))
      )
      .select(
        $"ip",
        $"eventTime",
        $"method",
        $"endpoint",
        $"statusCode",
        $"bytesSent",
        $"referrer",
        $"userAgent"
      )
      .as[ParsedLog]
      .cache()

    val validCount = parsedDs.count()
    val malformedCount = totalRawLines - validCount
    rawDf.unpersist()

    (parsedDs, totalRawLines, malformedCount)
  }
}
