# Cybersecurity Data Analytics: A Scala & Apache Spark Approach to Log Analysis

A **100% free, open-source** cybersecurity log analytics mini project built with **Scala 2.12**, **Apache Spark 3.5 (Spark SQL & Datasets)**, **sbt**, and an interactive **SIEM Dashboard** — ready to run locally in **VS Code** and deploy for free on **GitHub Pages** or **Cloudflare Pages**.

## What It Detects (Powered by Apache Spark)
1. **Brute-Force / Auth Abuse** — Sliding 5-minute windows flagging IPs with repeated HTTP `401`/`403` bursts.
2. **DDoS / Traffic Flood Spikes** — Per-minute request aggregations + Z-score anomaly detection in Spark SQL.
3. **Web Attack Payloads** — Regex signature matching for **SQL Injection**, **Cross-Site Scripting (XSS)**, and **Path Traversal** (`../../etc/passwd`).
4. **Directory / Vulnerability Scanning** — Flags reconnaissance bots (e.g., `gobuster`) generating high `404` error counts across distinct paths.
5. **Composite IP Risk Scoring** — Joins traffic metrics with weighted alert severity scores (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

## Project Structure
```text
cybersec-spark-log-analyzer/
├── build.sbt                                          # Scala 2.12 + Apache Spark 3.5 + Java 17 JVM flags
├── data/sample_access.log                             # Sample Apache/Nginx logs with realistic cyberattacks
├── src/main/scala/com/cybersec/
│   ├── Main.scala                                     # SparkSession entry point & pipeline runner
│   ├── models/LogModels.scala                         # Type-safe Scala case classes
│   ├── parser/LogParser.scala                         # Regex log ingestion into Spark Dataset[ParsedLog]
│   ├── analytics/ThreatDetector.scala                 # Spark SQL threat detection & IP risk profiling
│   ├── report/ReportExporter.scala                    # Windows-safe JSON/CSV & terminal report exporter
│   └── generator/LogGenerator.scala                   # Synthetic big-data log generator (10k+ rows)
├── dashboard/                                         # Zero-build SIEM web dashboard (HTML/CSS/JS + Chart.js)
└── .github/workflows/analyze-and-deploy.yml           # Free GitHub Actions + GitHub Pages CI/CD
```

## Step 1: One-Time Free Tool Install (Windows PowerShell)
Run these commands in PowerShell, then **restart VS Code**:
```powershell
winget install -e --id EclipseAdoptium.Temurin.17.JDK
winget install -e --id sbt.sbt
winget install -e --id Git.Git
```
In VS Code, install the recommended extension **Scala (Metals)** (`scalameta.metals`) when prompted.

## Step 2: Run in VS Code
Open this folder in VS Code, open the integrated terminal (`Ctrl + ~`), and run:
```powershell
sbt run
```
*(Or press `Ctrl + Shift + B` to run the preconfigured VS Code build task!)*

Want to test on a larger dataset (10,000 logs)?
```powershell
sbt "runMain com.cybersec.generator.LogGenerator data/large_access.log 10000"
sbt "runMain com.cybersec.Main data/large_access.log"
```

## Step 3: View the Dashboard Locally
- Run the built-in zero-dependency Java server right inside VS Code's terminal:
  ```powershell
  java ServeDashboard.java
  ```
  Then open `http://localhost:8000` in your browser!
- Or open `dashboard/index.html` using the **Live Server** VS Code extension.

## Step 4: Deploy 100% Free (GitHub Actions + GitHub Pages)
1. Create a free public repository on GitHub and push this folder:
   ```powershell
   git init
   git add .
   git commit -m "Initial Scala + Spark cybersecurity log analyzer"
   git branch -M main
   git remote add origin https://github.com/<your-username>/cybersec-spark-log-analyzer.git
   git push -u origin main
   ```
2. In your GitHub repo, go to **Settings → Pages → Source** and select **GitHub Actions**.
3. Every push automatically runs your **Scala + Apache Spark** pipeline on GitHub's free Linux runner and publishes the live SIEM dashboard URL!
