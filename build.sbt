ThisBuild / version := "0.1.0"
ThisBuild / scalaVersion := "2.12.19"
ThisBuild / organization := "com.cybersec"

val sparkVersion = "3.5.3"

lazy val root = (project in file("."))
  .settings(
    name := "cybersec-spark-log-analyzer",
    Compile / mainClass := Some("com.cybersec.Main"),
    libraryDependencies ++= Seq(
      "org.apache.spark" %% "spark-core" % sparkVersion,
      "org.apache.spark" %% "spark-sql"  % sparkVersion
    ),
    // Required so Apache Spark 3.5 runs smoothly on Java 17
    Compile / run / fork := true,
    Compile / run / javaOptions ++= Seq(
      "-Xmx2G",
      "--add-opens=java.base/java.lang=ALL-UNNAMED",
      "--add-opens=java.base/java.lang.invoke=ALL-UNNAMED",
      "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
      "--add-opens=java.base/java.io=ALL-UNNAMED",
      "--add-opens=java.base/java.net=ALL-UNNAMED",
      "--add-opens=java.base/java.nio=ALL-UNNAMED",
      "--add-opens=java.base/java.util=ALL-UNNAMED",
      "--add-opens=java.base/java.util.concurrent=ALL-UNNAMED",
      "--add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED",
      "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
      "--add-opens=java.base/sun.nio.cs=ALL-UNNAMED",
      "--add-opens=java.base/sun.security.action=ALL-UNNAMED",
      "--add-opens=java.base/sun.util.calendar=ALL-UNNAMED"
    )
  )
