const SEVERITY_COLOR = { CRITICAL: "var(--critical)", HIGH: "var(--high)", MEDIUM: "var(--medium)", LOW: "var(--low)" };
const SEVERITY_BG = { CRITICAL: "var(--critical-bg)", HIGH: "var(--high-bg)", MEDIUM: "var(--medium-bg)", LOW: "var(--low-bg)" };

const ICONS = {
  shield: '<path d="M10 2.5 4 4.8v5.2c0 4.2 2.6 7 6 8.5 3.4-1.5 6-4.3 6-8.5V4.8L10 2.5Z"/><path d="m7.3 10 1.9 1.9L12.9 8"/>',
};
function icon(name, size = 20, color = "white") {
  return `<svg width="${size}" height="${size}" viewBox="0 0 20 20" fill="none" stroke="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg>`;
}
document.getElementById("icon-shield").innerHTML = icon("shield");

function timeAgo(isoString) {
  if (!isoString) return "";
  const diff = (Date.now() - new Date(isoString + "Z")) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return Math.floor(diff / 60) + "m ago";
  if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
  return Math.floor(diff / 86400) + "d ago";
}

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error("Request failed: " + url);
  return res.json();
}


async function renderPipelineStatus() {
  const builds = await fetchJSON("/api/builds");
  const el = document.getElementById("pipeline-status");
  if (!builds.length) {
    el.innerHTML = `<div class="pipeline-empty">Waiting for the first Jenkins pipeline run.</div>`;
    return;
  }
  const b = builds[0];
  const status = b.pipeline_status || (b.gate_status === "PASS" ? "PASSED" : "FAILED");
  const gate = b.gate_status || "PENDING";
  const statusClass = status === "PASSED" ? "status-pass" : (status === "FAILED" ? "status-fail" : "status-running");
  const gateClass = gate === "PASS" ? "status-pass" : (gate === "FAIL" ? "status-fail" : "status-running");
  const jenkins = b.jenkins_url ? `<a href="${b.jenkins_url}" target="_blank" rel="noopener">Open Jenkins build</a>` : "";
  el.innerHTML = `
    <div class="pipeline-card">
      <div>
        <div class="pipeline-eyebrow">Latest pipeline · Build #${b.build_number}</div>
        <div class="pipeline-stage">${b.current_stage || "Pipeline activity"}</div>
        <div class="ticket-meta">${b.branch || "main"} · <span class="mono">${(b.commit_sha || "").slice(0, 8)}</span> ${jenkins ? "· " + jenkins : ""}</div>
      </div>
      <div class="pipeline-badges">
        <span class="pipeline-status ${statusClass}">${status}</span>
        <span class="pipeline-status ${gateClass}">Gate: ${gate}</span>
      </div>
    </div>`;
}
async function renderKPIs() {
  const builds = await fetchJSON("/api/builds");
  const latest = builds[0];
  const strip = document.getElementById("kpi-strip");
  if (!latest) {
    strip.innerHTML = `<div class="empty-state">No builds recorded yet. Push a commit to trigger the pipeline.</div>`;
    return;
  }
  const cards = [
    ["Critical", latest.critical_count, "var(--critical)"],
    ["High", latest.high_count, "var(--high)"],
    ["Medium", latest.medium_count, "var(--medium)"],
    ["Low", latest.low_count, "var(--low)"],
    ["Total findings", latest.total_count, "var(--text)"],
  ];
  strip.innerHTML = cards.map(([label, value, color]) =>
    `<div class="kpi-card"><div class="kpi-value" style="color:${color}">${value}</div><div class="kpi-label">${label}</div></div>`
  ).join("");
}

async function renderTrend() {
  const trends = await fetchJSON("/api/trends");
  const el = document.getElementById("trend-chart");
  if (!trends.length) {
    el.innerHTML = `<div class="empty-state">Trend will appear after a few builds have run.</div>`;
    return;
  }
  const maxTotal = Math.max(1, ...trends.map(t => t.critical_count + t.high_count + t.medium_count + t.low_count));
  el.innerHTML = `<div class="trend-bars">` + trends.map(t => {
    const total = t.critical_count + t.high_count + t.medium_count + t.low_count;
    const heightPct = Math.max(4, (total / maxTotal) * 100);
    const color = t.gate_status === "PASS" ? "var(--low)" : "var(--critical)";
    return `<div class="trend-bar-wrap">
      <div class="trend-bar" style="height:${heightPct}%;background:${color}" title="Build #${t.build_number}: ${total} findings (${t.gate_status})"></div>
      <div class="trend-label">#${t.build_number}</div>
    </div>`;
  }).join("") + `</div>`;
}

async function applyAiFix(ticketId, btn) {
  btn.disabled = true;
  btn.textContent = "Requesting...";
  try {
    const res = await fetchJSON(`/api/tickets/${ticketId}/apply-ai-fix`, { method: "POST" });
    btn.textContent = "Fix requested";
  } catch (e) {
    btn.textContent = "Failed - retry";
    btn.disabled = false;
  }
  renderTickets();
}

function showRemediationGuide(ticketId, guideText) {
  alert(guideText || "No remediation guide available for this issue.");
}

async function resolveManually(ticketId, btn) {
  btn.disabled = true;
  await fetchJSON(`/api/tickets/${ticketId}/resolve`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note: "Resolved manually by developer" }),
  });
  renderTickets();
}

async function renderTickets() {
  const tickets = await fetchJSON("/api/tickets");
  const open = tickets.filter(t => t.status !== "resolved");
  document.getElementById("ticket-count-badge").textContent = open.length;

  const list = document.getElementById("tickets-list");
  if (!open.length) {
    list.innerHTML = `<div class="empty-state">No open tickets. All findings resolved.</div>`;
    return;
  }

  list.innerHTML = open.map(t => {
    const color = SEVERITY_COLOR[t.severity] || "var(--text-muted)";
    const bg = SEVERITY_BG[t.severity] || "var(--border)";
    const remediationType = (t.remediation_type || "MANUAL").toUpperCase();
    const canApplyAi = t.status === "open" && ["AI_ELIGIBLE", "AI_ASSISTED"].includes(remediationType);
    const prLink = t.pr_url ? `<a href="${t.pr_url}" target="_blank" rel="noopener">View PR</a>` : "";
    const remediationReason = t.remediation_reason ? `<div class="ticket-meta" style="margin-top: 0.5rem; color: var(--text-muted);">${t.remediation_reason}</div>` : "";
    const beforeStatus = t.before_status || "BLOCKED";
    const afterStatus = t.after_status || "PENDING";
    const validationSummary = t.validation_summary || "Before: blocked. After: validation pending.";
    const guideButton = remediationType === "MANUAL"
      ? `<button class="btn" onclick="showRemediationGuide(${t.id}, ${JSON.stringify(t.remediation_guide || "No remediation guide available.")})">View remediation guide</button>`
      : `<button class="btn btn-primary" ${canApplyAi ? "" : "disabled"} onclick="applyAiFix(${t.id}, this)">${remediationType === "AI_ASSISTED" ? "Generate proposal" : "Apply AI fix"}</button>`;

    return `
    <div class="ticket-card">
      <div class="ticket-head">
        <div>
          <div class="ticket-title">${t.message || t.rule_id}</div>
          <div class="ticket-meta mono">${t.file_path || ""} &middot; ${t.rule_id || ""} &middot; build #${t.build_number}</div>
        </div>
        <div style="display:flex; gap:0.4rem; align-items:center; flex-wrap:wrap; justify-content:flex-end;">
          <span class="sev-pill" style="color:${color};background:${bg};border-color:${color}33">${t.severity}</span>
          <span class="status-pill status-${t.status}">${t.status.replace(/_/g, " ")}</span>
          <span class="status-pill" style="background: rgba(14,116,144,0.1); color: #0E7490; border-color: rgba(14,116,144,0.2);">${remediationType.replace(/_/g, " ")}</span>
        </div>
      </div>
      ${remediationReason}
      <div class="ticket-meta" style="margin-top: 0.5rem; color: var(--text-muted);">Before: <strong>${beforeStatus}</strong> &nbsp;|&nbsp; After: <strong>${afterStatus}</strong></div>
      <div class="ticket-meta" style="margin-top: 0.3rem; color: var(--text-muted);">${validationSummary}</div>
      ${t.ai_explanation ? `<p style="font-size:0.85rem;color:var(--text-muted);margin:0.6rem 0 0;">${t.ai_explanation} ${prLink}</p>` : ""}
      <div class="ticket-actions">
        ${guideButton}
        <button class="btn" onclick="resolveManually(${t.id}, this)">Mark resolved manually</button>
      </div>
    </div>`;
  }).join("");
}

async function renderHistory() {
  const builds = await fetchJSON("/api/builds");
  const list = document.getElementById("history-list");
  if (!builds.length) {
    list.innerHTML = `<div class="empty-state">No builds yet.</div>`;
    return;
  }
  list.innerHTML = builds.map(b => `
    <div class="build-row">
      <div class="build-left">
        <span class="build-badge ${b.gate_status === "PASS" ? "pass" : "fail"}"></span>
        <div>
          <div><strong>Build #${b.build_number}</strong> <span class="mono">${(b.commit_sha || "").slice(0, 8)}</span></div>
          <div class="ticket-meta">${b.branch || "main"} &middot; ${timeAgo(b.created_at)} ${b.deployed ? "&middot; deployed" : ""}</div>
        </div>
      </div>
      <div class="ticket-meta">${b.total_count} finding(s) &middot; ${b.gate_status}</div>
    </div>
  `).join("");
}

async function renderAudit() {
  const events = await fetchJSON("/api/audit-log");
  const list = document.getElementById("audit-list");
  if (!events.length) {
    list.innerHTML = `<div class="empty-state">No events logged yet.</div>`;
    return;
  }
  list.innerHTML = events.map(e => `
    <div class="audit-row">
      <div class="audit-event">${e.event.replace(/_/g, " ")}</div>
      <div class="ticket-meta">${e.detail || ""}</div>
      <div class="audit-time">${timeAgo(e.created_at)}</div>
    </div>
  `).join("");
}

function refreshAll() {
  renderPipelineStatus();
  renderKPIs();
  renderTrend();
  renderTickets();
  renderHistory();
  renderAudit();
}

document.querySelectorAll(".tab-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById("panel-" + btn.dataset.tab).classList.add("active");
  });
});

refreshAll();
setInterval(refreshAll, 10000); // poll every 10 seconds for "real-time" updates
