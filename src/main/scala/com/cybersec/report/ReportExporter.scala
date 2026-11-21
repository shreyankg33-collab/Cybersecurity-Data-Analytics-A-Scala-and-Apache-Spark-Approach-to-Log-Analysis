package com.cybersec.report

import com.cybersec.models._
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}

object ReportExporter {

  private def escJson(s: String): String = {
    if (s == null) ""
    else {
      val sb = new StringBuilder(s.length + 16)
      s.foreach {
        case '"'  => sb.append("\\\"")
        case '\\' => sb.append("\\\\")
        case '\b' => sb.append("\\b")
        case '\f' => sb.append("\\f")
        case '\n' => sb.append("\\n")
        case '\r' => sb.append("\\r")
        case '\t' => sb.append("\\t")
        case c if c < 0x20 => sb.append(f"\\u${c.toInt}%04x")
        case c    => sb.append(c)
      }
      sb.toString()
    }
  }

  private def escCsv(s: String): String = {
    val safe = if (s == null) "" else s
    if (safe.contains(",") || safe.contains("\"") || safe.contains("\n")) {
      "\"" + safe.replace("\"", "\"\"") + "\""
    } else safe
  }

  /**
   * Writes dashboard/data/report.json using Java NIO (avoids Windows Hadoop winutils.exe errors).
   */
  def writeJsonReport(summary: AnalysisSummary, outputPath: String): Unit = {
    val alertsJson = summary.alerts.map { a =>
      s"""    {
         |      "alertType": "${escJson(a.alertType)}",
         |      "severity": "${escJson(a.severity)}",
         |      "ip": "${escJson(a.ip)}",
         |      "eventCount": ${a.eventCount},
         |      "firstSeen": "${escJson(a.firstSeen)}",
         |      "lastSeen": "${escJson(a.lastSeen)}",
         |      "details": "${escJson(a.details)}"
         |    }""".stripMargin
    }.mkString(",\n")

    val ipsJson = summary.topRiskyIps.map { r =>
      s"""    {
         |      "ip": "${escJson(r.ip)}",
         |      "totalRequests": ${r.totalRequests},
         |      "errorRequests": ${r.errorRequests},
         |      "totalBytes": ${r.totalBytes},
         |      "alertCount": ${r.alertCount},
         |      "riskScore": ${r.riskScore},
         |      "riskLevel": "${escJson(r.riskLevel)}",
         |      "attackTypes": "${escJson(r.attackTypes)}"
         |    }""".stripMargin
    }.mkString(",\n")

    val timelineJson = summary.timeline.map { t =>
      s"""    { "minuteBucket": "${escJson(t.minuteBucket)}", "totalRequests": ${t.totalRequests}, "errorRequests": ${t.errorRequests} }"""
    }.mkString(",\n")

    val statusJson = summary.statusBreakdown.map { s =>
      s"""    { "statusGroup": "${escJson(s.statusGroup)}", "count": ${s.count} }"""
    }.mkString(",\n")

    val endpointsJson = summary.topEndpoints.map { e =>
      s"""    { "endpoint": "${escJson(e.endpoint)}", "hits": ${e.hits}, "errorHits": ${e.errorHits} }"""
    }.mkString(",\n")

    val json =
      s"""{
         |  "sourceFile": "${escJson(summary.sourceFile)}",
         |  "generatedAt": "${escJson(summary.generatedAt)}",
         |  "totalRawLines": ${summary.totalRawLines},
         |  "parsedLogs": ${summary.parsedLogs},
         |  "malformedLines": ${summary.malformedLines},
         |  "uniqueIps": ${summary.uniqueIps},
         |  "totalAlerts": ${summary.totalAlerts},
         |  "criticalAlerts": ${summary.criticalAlerts},
         |  "highAlerts": ${summary.highAlerts},
         |  "mediumAlerts": ${summary.mediumAlerts},
         |  "alerts": [
         |$alertsJson
         |  ],
         |  "topRiskyIps": [
         |$ipsJson
         |  ],
         |  "timeline": [
         |$timelineJson
         |  ],
         |  "statusBreakdown": [
         |$statusJson
         |  ],
         |  "topEndpoints": [
         |$endpointsJson
         |  ]
         |}
         |""".stripMargin

    val path = Paths.get(outputPath)
    if (path.getParent != null) Files.createDirectories(path.getParent)
    Files.write(path, json.getBytes(StandardCharsets.UTF_8))
  }

  /**
   * Writes detected alerts to a CSV file for Excel / SIEM ingestion.
   */
  def writeAlertsCsv(alerts: Seq[ThreatAlert], outputPath: String): Unit = {
    val header = "alert_type,severity,ip,event_count,first_seen,last_seen,details"
    val rows = alerts.map { a =>
      Seq(
        escCsv(a.alertType),
        escCsv(a.severity),
        escCsv(a.ip),
        a.eventCount.toString,
        escCsv(a.firstSeen),
        escCsv(a.lastSeen),
        escCsv(a.details)
      ).mkString(",")
    }
    val csvContent = (header +: rows).mkString("\n") + "\n"
    val path = Paths.get(outputPath)
    if (path.getParent != null) Files.createDirectories(path.getParent)
    Files.write(path, csvContent.getBytes(StandardCharsets.UTF_8))
  }

  def printConsoleSummary(summary: AnalysisSummary): Unit = {
    println("=" * 78)
    println("  CYBERSECURITY LOG ANALYTICS REPORT (SCALA + APACHE SPARK)")
    println("=" * 78)
    println(f"  Source File     : ${summary.sourceFile}")
    println(f"  Parsed Logs     : ${summary.parsedLogs} / ${summary.totalRawLines} (malformed: ${summary.malformedLines})")
    println(f"  Unique IPs      : ${summary.uniqueIps}")
    println(f"  Total Alerts    : ${summary.totalAlerts}  [CRITICAL: ${summary.criticalAlerts} | HIGH: ${summary.highAlerts} | MEDIUM: ${summary.mediumAlerts}]")
    println("-" * 78)
    println("  DETECTED THREAT ALERTS:")
    summary.alerts.foreach { a =>
      println(f"  [${a.severity}%-8s] ${a.alertType}%-27s | IP: ${a.ip}%-15s | Count: ${a.eventCount}%3d | ${a.details}")
    }
    println("-" * 78)
    println("  TOP RISKY IP PROFILES:")
    summary.topRiskyIps.filter(_.riskScore > 0).foreach { r =>
      println(f"  ${r.ip}%-15s | Risk: ${r.riskScore}%3d/100 (${r.riskLevel}%-8s) | Reqs: ${r.totalRequests}%4d | Errors: ${r.errorRequests}%4d | ${r.attackTypes}")
    }
    println("=" * 78)
  }
}
