const SEVERITY_COLOR = { CRITICAL: "var(--critical)", HIGH: "var(--high)", MEDIUM: "var(--medium)", LOW: "var(--low)" };
const SEVERITY_BG = { CRITICAL: "var(--critical-bg)", HIGH: "var(--high-bg)", MEDIUM: "var(--medium-bg)", LOW: "var(--low-bg)" };
let ticketGuides = new Map();

const ICONS = {
  shield: '<path d="M10 2.5 4 4.8v5.2c0 4.2 2.6 7 6 8.5 3.4-1.5 6-4.3 6-8.5V4.8L10 2.5Z"/><path d="m7.3 10 1.9 1.9L12.9 8"/>',
};
function icon(name, size = 20, color = "white") {
  return `<svg width="${size}" height="${size}" viewBox="0 0 20 20" fill="none" stroke="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${ICONS[name] || ""}</svg>`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
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
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = body.detail || body.error || "";
    } catch (_) {
      detail = "";
    }
    throw new Error(detail || `Request failed (${res.status}): ${url}`);
  }
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
  const actions = btn.closest(".ticket-actions");
  let feedback = actions.querySelector(".ticket-action-feedback");
  if (!feedback) {
    feedback = document.createElement("p");
    feedback.className = "ticket-action-feedback";
    feedback.setAttribute("role", "status");
    actions.append(feedback);
  }
  feedback.textContent = "";
  try {
    await fetchJSON(`/api/tickets/${ticketId}/apply-ai-fix`, { method: "POST" });
    renderTickets();
  } catch (e) {
    btn.textContent = "Retry AI fix";
    btn.disabled = false;
    feedback.textContent = e.message;
  }
}

function showRemediationGuide(ticketId) {
  const ticket = ticketGuides.get(Number(ticketId));
  const dialog = document.getElementById("remediation-dialog");
  const content = document.getElementById("remediation-guide-content");
  const labels = {
    "why this happened": "Why it was flagged",
    "what went wrong": "Why it matters",
    "how to fix it": "How to fix it",
    "verification": "Verify the change",
  };
  const sections = new Map();
  const guideLines = (ticket?.remediation_guide || "Review the affected file, make a focused security fix, and rerun the relevant checks.").split(/\r?\n/);

  guideLines.forEach(line => {
    const match = line.match(/^(Why this happened|What went wrong|How to fix it|Verification):\s*(.*)$/i);
    if (match) {
      sections.set(match[1].toLowerCase(), match[2]);
    } else if (line.trim() && sections.size) {
      const lastKey = Array.from(sections.keys()).pop();
      sections.set(lastKey, `${sections.get(lastKey)} ${line.trim()}`);
    }
  });

  const findingText = `${ticket?.message || ""} ${ticket?.rule_id || ""} ${ticket?.file_path || ""}`.toLowerCase();
  const examples = [
    {
      match: /immutable|non-latest|latest image/,
      title: "Pin the container image",
      text: "Use a specific release tag or image digest instead of latest. The deployment pipeline should use the same immutable tag that passed scanning.",
      code: "image: my-app:1.4.2",
    },
    {
      match: /runasnonroot|non-root/,
      title: "Run the container as a non-root user",
      text: "Set the pod security context and make sure the image itself has a non-root user configured.",
      code: "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
    },
    {
      match: /allowprivilegeescalation|privilege escalation/,
      title: "Prevent privilege escalation",
      text: "Add this to the container security context. It prevents a process from gaining more privileges than its parent process.",
      code: "securityContext:\n  allowPrivilegeEscalation: false",
    },
    {
      match: /cpu\/memory limits|resource limits|resources/,
      title: "Set resource requests and limits",
      text: "Choose values suitable for the application. Requests reserve capacity; limits cap its maximum use.",
      code: "resources:\n  requests:\n    cpu: \"100m\"\n    memory: \"128Mi\"\n  limits:\n    cpu: \"250m\"\n    memory: \"256Mi\"",
    },
    {
      match: /dockerfile.*non-root|non-root.*user instruction/,
      title: "Use a non-root image user",
      text: "For the official Node image, switch to its built-in node account after copying the application files.",
      code: "USER node",
    },
    {
      match: /secret|credential|api key|token/,
      title: "Rotate and remove the exposed secret",
      text: "Revoke or rotate the credential first. Remove it from the working tree, load future values from a secret manager or environment variable, and check repository history for copies. Do not send the secret value to an AI service.",
    },
  ].find(example => example.match.test(findingText));

  if (examples) sections.set("how to fix it", examples.text);

  document.getElementById("guide-finding-title").textContent = ticket?.message || ticket?.rule_id || "Security finding";
  document.getElementById("guide-severity").textContent = ticket?.severity || "Finding";
  document.getElementById("guide-severity").className = `guide-severity severity-${(ticket?.severity || "").toLowerCase()}`;
  document.getElementById("guide-location").textContent = [ticket?.file_path, ticket?.rule_id, ticket?.source].filter(Boolean).join("  /  ");

  const sectionOrder = ["why this happened", "what went wrong", "how to fix it", "verification"];
  content.replaceChildren();
  sectionOrder.forEach((key, index) => {
    const text = sections.get(key);
    if (!text) return;
    const section = document.createElement("section");
    section.className = "guide-section";
    const number = document.createElement("span");
    number.className = "guide-step-number";
    number.textContent = String(index + 1).padStart(2, "0");
    const detail = document.createElement("div");
    const heading = document.createElement("h3");
    heading.textContent = labels[key];
    const paragraph = document.createElement("p");
    paragraph.textContent = text;
    detail.append(heading, paragraph);
    if (key === "how to fix it" && examples?.code) {
      const exampleTitle = document.createElement("p");
      exampleTitle.className = "guide-example-title";
      exampleTitle.textContent = examples.title;
      const code = document.createElement("pre");
      code.className = "guide-example";
      code.textContent = examples.code;
      detail.append(exampleTitle, code);
    }
    section.append(number, detail);
    content.append(section);
  });

  dialog.showModal();
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
  ticketGuides = new Map(tickets.map(ticket => [Number(ticket.id), ticket]));
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
    const ticketStatus = String(t.status || "open");
    const containsSecret = String(t.source || "").toLowerCase() === "gitleaks" || /secret|credential|password|api[ _-]?key|token/i.test(`${t.rule_id || ""} ${t.message || ""}`);
    const fallbackEligible = ["LOW", "MEDIUM"].includes(String(t.severity || "").toUpperCase()) && !containsSecret;
    const severityEligible = typeof t.ai_eligible === "boolean" ? t.ai_eligible : fallbackEligible;
    const requiresManualReview = ticketStatus === "manual_review_required";
    const remediationType = severityEligible && !requiresManualReview ? "AI_ELIGIBLE" : "MANUAL";
    const canApplyAi = ticketStatus === "open" && severityEligible && t.ai_action_available !== false;
    const vulnerabilityId = t.vulnerability_id || t.rule_id || "Unknown finding";
    const packageVersion = t.package_name
      ? `${t.package_name}${t.installed_version ? ` ${t.installed_version}` : ""}${t.fixed_version && t.fixed_version !== "-" ? ` -> ${t.fixed_version}` : ""}`
      : "";
    const safePrUrl = /^https:\/\/github\.com\/[^\s]+\/pull\/\d+\/?$/.test(String(t.pr_url || "")) ? t.pr_url : "";
    const prLink = safePrUrl ? `<a href="${escapeHtml(safePrUrl)}" target="_blank" rel="noopener">View PR</a>` : "";
    const remediationReasonText = t.ai_block_reason || (requiresManualReview
      ? "The previous AI attempt did not pass validation. Manual remediation and review are required."
      : severityEligible
        ? (t.ai_action_available === false ? "Jenkins is not configured. Set JENKINS_USER and JENKINS_API_TOKEN in the local .env file, then recreate the dashboard container." : "LOW/MEDIUM finding; a constrained Groq proposal can be validated before PR review.")
        : (t.remediation_reason || "HIGH/CRITICAL or secret finding; manual remediation and review are required."));
    const remediationReason = `<div class="ticket-meta" style="margin-top: 0.5rem; color: var(--text-muted);">${escapeHtml(remediationReasonText)}</div>`;
    const beforeStatus = t.before_status || "BLOCKED";
    const afterStatus = t.after_status || "PENDING";
    const validationSummary = t.validation_summary || "Before: blocked. After: validation pending.";
    const guideButton = remediationType === "MANUAL"
      ? `<button class="btn" data-guide-ticket="${t.id}">View remediation guide</button>`
      : `<button class="btn btn-primary" ${canApplyAi ? "" : "disabled"} onclick="applyAiFix(${t.id}, this)">Apply AI fix</button>`;

    return `
    <div class="ticket-card">
      <div class="ticket-head">
        <div>
          <div class="ticket-title">${escapeHtml(t.message || t.rule_id)}</div>
          <div class="ticket-meta mono">${escapeHtml(t.file_path || "")} &middot; ID ${escapeHtml(vulnerabilityId)}${packageVersion ? ` &middot; ${escapeHtml(packageVersion)}` : ""} &middot; build #${escapeHtml(t.build_number)}</div>
        </div>
        <div style="display:flex; gap:0.4rem; align-items:center; flex-wrap:wrap; justify-content:flex-end;">
          <span class="sev-pill" style="color:${color};background:${bg};border-color:${color}33">${escapeHtml(t.severity)}</span>
          <span class="status-pill status-${escapeHtml(ticketStatus)}">${escapeHtml(ticketStatus.replace(/_/g, " "))}</span>
          <span class="status-pill" style="background: rgba(14,116,144,0.1); color: #0E7490; border-color: rgba(14,116,144,0.2);">${escapeHtml(remediationType.replace(/_/g, " "))}</span>
        </div>
      </div>
      ${remediationReason}
      <div class="ticket-meta" style="margin-top: 0.5rem; color: var(--text-muted);">Before: <strong>${escapeHtml(beforeStatus)}</strong> &nbsp;|&nbsp; After: <strong>${escapeHtml(afterStatus)}</strong></div>
      <div class="ticket-meta" style="margin-top: 0.3rem; color: var(--text-muted);">${escapeHtml(validationSummary)}</div>
      ${t.ai_analysis ? `<div class="ticket-meta" style="margin-top: 0.55rem;"><strong>AI analysis:</strong> ${escapeHtml(t.ai_analysis)}</div>` : ""}
      ${t.proposed_remediation ? `<div class="ticket-meta" style="margin-top: 0.35rem;"><strong>Proposed fix:</strong> ${escapeHtml(t.proposed_remediation)}</div>` : ""}
      ${(t.files_changed && t.files_changed !== "[]") ? `<div class="ticket-meta" style="margin-top: 0.35rem;"><strong>Files changed:</strong> ${escapeHtml(Array.isArray(t.files_changed) ? t.files_changed.join(", ") : t.files_changed)}</div>` : ""}
      ${(t.test_status && t.test_status !== "NOT_RUN") || (t.rescan_status && t.rescan_status !== "NOT_RUN") ? `<div class="ticket-meta" style="margin-top: 0.35rem;"><strong>Tests:</strong> ${escapeHtml(t.test_status || "NOT_RUN")} &nbsp; <strong>Rescan:</strong> ${escapeHtml(t.rescan_status || "NOT_RUN")} &nbsp; <strong>Remediation:</strong> ${escapeHtml(t.remediation_status || "PENDING")}</div>` : ""}
      ${t.ai_explanation ? `<p style="font-size:0.85rem;color:var(--text-muted);margin:0.6rem 0 0;">${escapeHtml(t.ai_explanation)} ${prLink}</p>` : ""}
      <div class="ticket-actions">
        ${guideButton}
        <button class="btn" onclick="resolveManually(${t.id}, this)">Mark resolved manually</button>
      </div>
    </div>`;
  }).join("");
}

document.getElementById("tickets-list").addEventListener("click", event => {
  const button = event.target.closest("[data-guide-ticket]");
  if (button) showRemediationGuide(button.dataset.guideTicket);
});

document.querySelectorAll("[data-close-guide]").forEach(button => {
  button.addEventListener("click", () => document.getElementById("remediation-dialog").close());
});

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
