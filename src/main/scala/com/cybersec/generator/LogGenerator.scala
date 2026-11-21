package com.cybersec.generator

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.time.{ZoneOffset, ZonedDateTime}
import java.time.format.DateTimeFormatter
import java.util.Locale
import scala.util.Random

/**
 * Generates realistic Apache/Nginx combined logs with embedded cyberattacks
 * for stress-testing the Scala + Apache Spark pipeline.
 *
 * Usage: sbt "runMain com.cybersec.generator.LogGenerator data/large_access.log 10000"
 */
object LogGenerator {

  private val ApacheFormatter =
    DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.US)

  private val NormalIps = Vector(
    "10.0.1.12", "10.0.1.24", "10.0.1.35", "10.0.2.18", "10.0.2.41",
    "172.16.0.14", "172.16.0.29", "192.168.10.5", "192.168.10.19", "192.168.10.42"
  )

  private val NormalEndpoints = Vector(
    "/", "/index.html", "/api/products", "/api/profile", "/assets/app.js",
    "/assets/styles.css", "/about", "/docs", "/api/health", "/dashboard"
  )

  private val NormalAgents = Vector(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Firefox/129.0"
  )

  private val SqliPayloads = Vector(
    "/api/users?id=1%20OR%201=1",
    "/api/items?q=test'%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/search?term=admin';--",
    "/api/orders?id=5;DROP%20TABLE%20sessions"
  )

  private val XssPayloads = Vector(
    "/search?q=<script>alert(1)</script>",
    "/comments?body=%3Cscript%3Edocument.cookie%3C/script%3E",
    "/profile?bio=<img%20src=x%20onerror=alert(1)>"
  )

  private val TraversalPayloads = Vector(
    "/download?file=../../../../etc/passwd",
    "/static/..%2f..%2f..%2fetc/shadow",
    "/view?template=../../../windows/win.ini"
  )

  private val ReconPaths = Vector(
    "/wp-admin", "/.env", "/phpmyadmin", "/admin.bak", "/config.php",
    "/backup.zip", "/.git/config", "/server-status", "/xmlrpc.php",
    "/api/v1/debug", "/db_backup.sql", "/wp-login.php", "/shell.php", "/test.php"
  )

  def main(args: Array[String]): Unit = {
    val outputPath = args.headOption.getOrElse("data/large_access.log")
    val totalLines = if (args.length > 1) args(1).toInt else 5000
    val rng = new Random(42)
    val startTime = ZonedDateTime.of(2026, 11, 21, 9, 0, 0, 0, ZoneOffset.UTC)

    val lines = (0 until totalLines).map { i =>
      val ts = startTime.plusSeconds((i.toLong * 1800L) / math.max(1, totalLines))
      val formattedTs = ts.format(ApacheFormatter)
      val roll = rng.nextDouble()

      if (roll < 0.74) {
        // Normal user traffic
        val ip = NormalIps(rng.nextInt(NormalIps.size))
        val ep = NormalEndpoints(rng.nextInt(NormalEndpoints.size))
        val status = if (rng.nextDouble() < 0.96) 200 else 304
        val bytes = 512 + rng.nextInt(14000)
        val ua = NormalAgents(rng.nextInt(NormalAgents.size))
        s"""$ip - - [$formattedTs] "GET $ep HTTP/1.1" $status $bytes "-" "$ua""""
      } else if (roll < 0.83) {
        // Brute-force login attacks
        val ip = if (rng.nextBoolean()) "185.220.101.44" else "91.240.118.172"
        val status = if (rng.nextDouble() < 0.8) 401 else 403
        s"""$ip - - [$formattedTs] "POST /api/login HTTP/1.1" $status 312 "-" "Hydra/9.5""""
      } else if (roll < 0.91) {
        // DDoS flood burst concentrated into minute 10
        val burstTs = startTime.plusMinutes(10).plusSeconds(rng.nextInt(58)).format(ApacheFormatter)
        s"""203.0.113.77 - - [$burstTs] "GET /api/products HTTP/1.1" 503 184 "-" "python-requests/2.31""""
      } else if (roll < 0.96) {
        // Recon / directory scan
        val path = ReconPaths(rng.nextInt(ReconPaths.size))
        s"""198.51.100.23 - - [$formattedTs] "GET $path HTTP/1.1" 404 209 "-" "gobuster/3.6""""
      } else {
        // SQLi / XSS / Path Traversal attacks
        val sub = rng.nextInt(3)
        sub match {
          case 0 =>
            val p = SqliPayloads(rng.nextInt(SqliPayloads.size))
            s"""45.155.205.91 - - [$formattedTs] "GET $p HTTP/1.1" 400 280 "-" "sqlmap/1.8""""
          case 1 =>
            val p = XssPayloads(rng.nextInt(XssPayloads.size))
            s"""103.145.12.88 - - [$formattedTs] "GET $p HTTP/1.1" 200 1240 "-" "Mozilla/5.0""""
          case _ =>
            val p = TraversalPayloads(rng.nextInt(TraversalPayloads.size))
            s"""45.155.205.91 - - [$formattedTs] "GET $p HTTP/1.1" 403 256 "-" "curl/8.4.0""""
        }
      }
    }

    val path = Paths.get(outputPath)
    if (path.getParent != null) Files.createDirectories(path.getParent)
    Files.write(path, (lines.mkString("\n") + "\n").getBytes(StandardCharsets.UTF_8))
    println(s"Generated $totalLines synthetic cybersecurity log entries at: $outputPath")
  }
}
