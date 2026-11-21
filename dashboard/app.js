let currentReport = null;
let timelineChart = null;
let statusChart = null;

function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function riskColor(level) {
  if (level === "CRITICAL") return "#ef4444";
  if (level === "HIGH") return "#f97316";
  if (level === "MEDIUM") return "#eab308";
  return "#22c55e";
}

function renderReport(data) {
  currentReport = data;
  document.getElementById("emptyBanner").classList.add("hidden");

  document.getElementById("metaInfo").textContent =
    `Source: ${data.sourceFile} • Generated: ${new Date(data.generatedAt).toLocaleString()}`;

  document.getElementById("kpiParsed").textContent = data.parsedLogs.toLocaleString();
  document.getElementById("kpiMalformed").textContent = `Malformed lines: ${data.malformedLines}`;
  document.getElementById("kpiIps").textContent = data.uniqueIps.toLocaleString();
  document.getElementById("kpiCritical").textContent = data.criticalAlerts.toLocaleString();
  document.getElementById("kpiTotalAlerts").textContent = `Total alerts: ${data.totalAlerts}`;
  document.getElementById("kpiHighMed").textContent =
    `${data.highAlerts} / ${data.mediumAlerts}`;

  renderTimelineChart(data.timeline || []);
  renderStatusChart(data.statusBreakdown || []);
  renderAlertsTable();
  renderRiskyIps(data.topRiskyIps || []);
  renderTopEndpoints(data.topEndpoints || []);
}

function renderTimelineChart(timeline) {
  const ctx = document.getElementById("timelineChart").getContext("2d");
  if (timelineChart) timelineChart.destroy();

  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: timeline.map((p) => p.minuteBucket),
      datasets: [
        {
          label: "Total Requests",
          data: timeline.map((p) => p.totalRequests),
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.14)",
          fill: true,
          tension: 0.3,
        },
        {
          label: "Error Requests (4xx/5xx)",
          data: timeline.map((p) => p.errorRequests),
          borderColor: "#ef4444",
          backgroundColor: "rgba(239, 68, 68, 0.14)",
          fill: true,
          tension: 0.3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: "#cbd5e1" } } },
      scales: {
        x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
        y: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" }, beginAtZero: true },
      },
    },
  });
}

function renderStatusChart(breakdown) {
  const ctx = document.getElementById("statusChart").getContext("2d");
  if (statusChart) statusChart.destroy();

  statusChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: breakdown.map((s) => s.statusGroup),
      datasets: [
        {
          data: breakdown.map((s) => s.count),
          backgroundColor: ["#22c55e", "#38bdf8", "#f97316", "#ef4444", "#a855f7"],
          borderColor: "#121a2f",
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1" } } },
    },
  });
}

function renderAlertsTable() {
  if (!currentReport) return;
  const sev = document.getElementById("severityFilter").value;
  const q = document.getElementById("searchInput").value.trim().toLowerCase();

  const filtered = (currentReport.alerts || []).filter((a) => {
    const matchSev = sev === "ALL" || a.severity === sev;
    const hay = `${a.alertType} ${a.ip} ${a.details}`.toLowerCase();
    return matchSev && (!q || hay.includes(q));
  });

  const tbody = document.getElementById("alertsTableBody");
  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:#8ea0c0;">No matching alerts found.</td></tr>`;
    return;
  }

  tbody.innerHTML = filtered
    .map(
      (a) => `
      <tr>
        <td><span class="badge badge-${escHtml(a.severity)}">${escHtml(a.severity)}</span></td>
        <td><strong>${escHtml(a.alertType)}</strong></td>
        <td class="mono">${escHtml(a.ip)}</td>
        <td>${a.eventCount}</td>
        <td class="mono">${escHtml(a.firstSeen)} &rarr; ${escHtml(a.lastSeen.slice(11))}</td>
        <td>${escHtml(a.details)}</td>
      </tr>`
    )
    .join("");
}

function renderRiskyIps(ips) {
  const tbody = document.getElementById("riskyIpsBody");
  tbody.innerHTML = ips
    .map(
      (r) => `
      <tr>
        <td class="mono">${escHtml(r.ip)}</td>
        <td>
          <div class="risk-bar">
            <div class="risk-track">
              <div class="risk-fill" style="width:${r.riskScore}%;background:${riskColor(r.riskLevel)}"></div>
            </div>
            <span class="badge badge-${escHtml(r.riskLevel)}">${r.riskScore}</span>
          </div>
        </td>
        <td>${r.totalRequests}</td>
        <td>${r.errorRequests}</td>
        <td>${escHtml(r.attackTypes)}</td>
      </tr>`
    )
    .join("");
}

function renderTopEndpoints(endpoints) {
  const tbody = document.getElementById("endpointsBody");
  tbody.innerHTML = endpoints
    .map(
      (e) => `
      <tr>
        <td class="mono">${escHtml(e.endpoint)}</td>
        <td>${e.hits}</td>
        <td>${e.errorHits}</td>
      </tr>`
    )
    .join("");
}

document.getElementById("severityFilter").addEventListener("change", renderAlertsTable);
document.getElementById("searchInput").addEventListener("input", renderAlertsTable);

document.getElementById("jsonFileInput").addEventListener("change", (ev) => {
  const file = ev.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      renderReport(JSON.parse(reader.result));
    } catch (err) {
      alert("Invalid JSON file: " + err.message);
    }
  };
  reader.readAsText(file);
});

async function loadDefaultReport() {
  try {
    const res = await fetch("data/report.json", { cache: "no-store" });
    if (!res.ok) throw new Error("Not generated yet");
    const data = await res.json();
    renderReport(data);
  } catch {
    document.getElementById("emptyBanner").classList.remove("hidden");
  }
}

loadDefaultReport();
