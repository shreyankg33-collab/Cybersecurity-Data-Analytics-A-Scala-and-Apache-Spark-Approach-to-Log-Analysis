package com.cybersec.models

import java.sql.Timestamp

final case class ParsedLog(
  ip: String,
  eventTime: Timestamp,
  method: String,
  endpoint: String,
  statusCode: Int,
  bytesSent: Long,
  referrer: String,
  userAgent: String
)

final case class ThreatAlert(
  alertType: String,
  severity: String,
  ip: String,
  eventCount: Long,
  firstSeen: String,
  lastSeen: String,
  details: String
)

final case class IpRiskProfile(
  ip: String,
  totalRequests: Long,
  errorRequests: Long,
  totalBytes: Long,
  alertCount: Long,
  riskScore: Int,
  riskLevel: String,
  attackTypes: String
)

final case class TimelinePoint(
  minuteBucket: String,
  totalRequests: Long,
  errorRequests: Long
)

final case class StatusCount(
  statusGroup: String,
  count: Long
)

final case class EndpointMetric(
  endpoint: String,
  hits: Long,
  errorHits: Long
)

final case class AnalysisSummary(
  sourceFile: String,
  generatedAt: String,
  totalRawLines: Long,
  parsedLogs: Long,
  malformedLines: Long,
  uniqueIps: Long,
  totalAlerts: Long,
  criticalAlerts: Long,
  highAlerts: Long,
  mediumAlerts: Long,
  alerts: Seq[ThreatAlert],
  topRiskyIps: Seq[IpRiskProfile],
  timeline: Seq[TimelinePoint],
  statusBreakdown: Seq[StatusCount],
  topEndpoints: Seq[EndpointMetric]
)
