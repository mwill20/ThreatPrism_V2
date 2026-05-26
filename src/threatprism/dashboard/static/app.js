const ROLE_PROFILES = {
  analyst: {
    label: "Analyst",
    role: "analyst",
    credential: "demo-analyst-key",
    queueTitle: "Analyst cases",
    purpose: "analyst_investigation",
  },
  manager_grc: {
    label: "Manager/GRC",
    role: "manager_grc",
    credential: "demo-manager-key",
    queueTitle: "Manager review",
    purpose: "manager_review",
  },
  legal_privacy: {
    label: "Legal/Privacy",
    role: "legal_privacy",
    credential: "demo-legal-key",
    queueTitle: "Healthcare review",
    purpose: "legal_privacy_review",
  },
  audit_debug: {
    label: "Audit/Debug",
    role: "audit_debug",
    credential: "demo-audit-key",
    queueTitle: "Audit detail",
    purpose: "audit_reconstruction",
  },
  engineer: {
    label: "Engineer",
    role: "engineer",
    credential: "demo-engineer-key",
    queueTitle: "Engineering cases",
    purpose: "engineering_debug",
  },
  csi_rgoi: {
    label: "CSI/RGOI",
    role: "analyst",
    credential: "demo-analyst-key",
    queueTitle: "Cognitive objects",
    purpose: "analyst_investigation",
  },
};

const API_ROUTES = {
  health: "/health",
  metrics: "/metrics",
  cases: "/cases/read-model",
  managerQueue: "/queues/manager-review",
  healthcareQueue: "/queues/healthcare-review",
  caseDetail: "/cases/{case_id}",
  evidence: "/cases/{case_id}/evidence",
  timeline: "/cases/{case_id}/timeline",
  mitre: "/cases/{case_id}/mitre",
  grc: "/cases/{case_id}/grc-controls",
  audit: "/cases/{case_id}/audit-events",
  csiObjects: "/csi/objects",
  csiDetail: "/csi/objects/{object_id}",
  csiLineage: "/csi/lineage/{object_id}",
  csiReplay: "/csi/replay/{object_id}",
  csiObservability: "/csi/observability",
  csiDivergence: "/csi/divergence",
};

const DEMO_CASE = {
  source: "generic_soar",
  source_case_id: "SOAR-DASHBOARD-UI-001",
  organization_context: {
    environment: "demo",
    business_unit: "internal_soc",
    sensitivity: "demo",
    operating_model: "mssp_to_internal_soc_transition",
  },
  title: "Suspicious sign-in followed by mailbox rule creation",
  description:
    "Synthetic dashboard case involving demo.user@example.invalid, source IP 203.0.113.42, and mailbox rule creation.",
  created_at: "2026-05-26T14:00:00Z",
  alerts: [
    {
      alert_id: "alert-dashboard-001",
      name: "Impossible travel sign-in",
      severity: "medium",
      source: "identity_provider",
      description: "Synthetic sign-in sequence from distant locations.",
    },
  ],
  events: [
    {
      event_id: "evt-dashboard-001",
      timestamp: "2026-05-26T13:56:00Z",
      event_type: "signin",
      source: "identity_provider",
      description: "Successful sign-in from 203.0.113.42 followed by mailbox rule creation.",
      normalized: {
        actor: "demo.user@example.invalid",
        source_ip: "203.0.113.42",
      },
      provenance: {
        source_file: "demo://dashboard/generic_soar_case.json",
        record_index: 0,
        source_event_id: "source-dashboard-001",
      },
      raw_reference: "demo://events/evt-dashboard-001",
    },
  ],
  entities: [
    {
      entity_type: "user",
      value: "demo.user@example.invalid",
      role: "subject",
    },
  ],
  iocs: [
    {
      ioc_type: "ip",
      value: "203.0.113.42",
      source: "alert",
      confidence: 0.7,
      evidence_ids: ["ev-dashboard-001"],
    },
  ],
  evidence: [
    {
      evidence_id: "ev-dashboard-001",
      evidence_type: "log",
      summary:
        "Synthetic identity log shows unfamiliar source IP 203.0.113.42 and mailbox rule creation for demo.user@example.invalid.",
      source_uri: "demo://logs/dashboard/evt-dashboard-001",
      event_ids: ["evt-dashboard-001"],
      excerpt: "Successful sign-in from 203.0.113.42 followed by mailbox rule creation.",
      sensitivity: "demo",
      provenance: {
        source_file: "demo://dashboard/generic_soar_case.json",
        record_index: 0,
        source_event_id: "source-dashboard-001",
      },
    },
  ],
};

const state = {
  persona: "analyst",
  health: null,
  metrics: null,
  cases: [],
  managerQueue: [],
  healthcareQueue: [],
  csi: null,
  selectedCaseId: null,
  detail: null,
  evidence: null,
  timeline: null,
  mitre: null,
  grc: null,
  audit: null,
  loading: false,
};

const $ = (id) => document.getElementById(id);

function profile() {
  return ROLE_PROFILES[state.persona];
}

function headers() {
  return {
    "Content-Type": "application/json",
    "X-ThreatPrism-Demo-Key": profile().credential,
  };
}

function withRole(path, params = {}) {
  const url = new URL(path, window.location.origin);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      url.searchParams.set(key, value);
    }
  });
  if (!url.searchParams.has("role")) {
    url.searchParams.set("role", profile().role);
  }
  return `${url.pathname}${url.search}`;
}

async function apiGet(path, params = {}) {
  const response = await fetch(withRole(path, params), { headers: headers() });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

async function apiGetOptional(path, params = {}) {
  try {
    return await apiGet(path, params);
  } catch (error) {
    return {
      items: [],
      unavailable: true,
      error: error.message,
    };
  }
}

async function refreshDashboard() {
  state.loading = true;
  renderLoading();
  try {
    const [health, metrics, cases, managerQueue, healthcareQueue, csi] = await Promise.all([
      fetch(API_ROUTES.health).then((response) => response.json()),
      apiGet(API_ROUTES.metrics),
      apiGet(API_ROUTES.cases, caseFilters()),
      apiGet(API_ROUTES.managerQueue, { limit: 25 }),
      apiGet(API_ROUTES.healthcareQueue, { limit: 25 }),
      apiGet(API_ROUTES.csiObjects, {
        tenant_id: "tenant_demo_alpha",
        query: "identity",
        purpose: profile().purpose,
        limit: 8,
      }).catch((error) => ({ items: [], total: 0, error: error.message })),
    ]);
    state.health = health;
    state.metrics = metrics;
    state.cases = cases.items || [];
    state.managerQueue = managerQueue.items || [];
    state.healthcareQueue = healthcareQueue.items || [];
    state.csi = csi;
    if (!state.selectedCaseId && state.cases.length) {
      state.selectedCaseId = state.cases[0].case_id;
    }
    await refreshDetail();
  } catch (error) {
    renderError(error.message);
  } finally {
    state.loading = false;
    render();
  }
}

async function refreshDetail() {
  if (!state.selectedCaseId) {
    state.detail = null;
    state.evidence = null;
    state.timeline = null;
    state.mitre = null;
    state.grc = null;
    state.audit = null;
    return;
  }
  const casePath = (route) => route.replace("{case_id}", state.selectedCaseId);
  const [detail, evidence, timeline, mitre, grc, audit] = await Promise.all([
    apiGet(casePath(API_ROUTES.caseDetail)),
    apiGetOptional(casePath(API_ROUTES.evidence)),
    apiGetOptional(casePath(API_ROUTES.timeline)),
    apiGetOptional(casePath(API_ROUTES.mitre)),
    apiGetOptional(casePath(API_ROUTES.grc)),
    apiGetOptional(casePath(API_ROUTES.audit)),
  ]);
  state.detail = detail;
  state.evidence = evidence;
  state.timeline = timeline;
  state.mitre = mitre;
  state.grc = grc;
  state.audit = audit;
}

function caseFilters() {
  const filters = { limit: 25 };
  const status = $("status-filter").value;
  const severity = $("severity-filter").value;
  if (status) {
    filters.status = status;
  }
  if (severity) {
    filters.severity = severity;
  }
  if (state.persona === "manager_grc") {
    filters.manager_review_required = true;
  }
  if (state.persona === "legal_privacy") {
    filters.healthcare_review_required = true;
  }
  return filters;
}

async function seedCase() {
  $("seed-case").disabled = true;
  try {
    const payload = JSON.parse(JSON.stringify(DEMO_CASE));
    payload.source_case_id = `SOAR-DASHBOARD-UI-${Date.now()}`;
    const response = await fetch("/cases", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    const accepted = await response.json();
    state.selectedCaseId = accepted.case_id;
    window.setTimeout(refreshDashboard, 600);
  } catch (error) {
    renderError(error.message);
  } finally {
    $("seed-case").disabled = false;
  }
}

function render() {
  renderRoleControls();
  renderHealth();
  renderMetrics();
  renderCases();
  renderDetail();
  renderInsights();
}

function renderRoleControls() {
  document.querySelectorAll(".role-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.persona === state.persona);
  });
  $("queue-title").textContent = profile().queueTitle;
  $("active-persona").textContent = profile().label;
}

function renderHealth() {
  const healthStatus = $("health-status");
  const actionStatus = $("action-status");
  if (!state.health) {
    healthStatus.textContent = "API unavailable";
    healthStatus.className = "pill danger";
    return;
  }
  healthStatus.textContent = `${state.health.service || "threatprism-api"} ${state.health.status}`;
  healthStatus.className = "pill ok";
  const realActions = state.health.allow_real_actions === true;
  actionStatus.textContent = realActions ? "ALLOW_REAL_ACTIONS=true" : "ALLOW_REAL_ACTIONS=false";
  actionStatus.className = realActions ? "pill danger" : "pill ok";
}

function renderMetrics() {
  const metrics = state.metrics || {};
  $("metric-total").textContent = metrics.case_counts?.total ?? 0;
  $("metric-completed").textContent = metrics.triage?.completed ?? 0;
  $("metric-blocked").textContent = metrics.guardrails?.blocked_cases ?? 0;
  $("metric-manager").textContent = metrics.disagreement?.manager_review_required_count ?? 0;
  $("metric-healthcare").textContent = metrics.guardrails?.healthcare_review_required ?? 0;
  $("metric-auth").textContent = metrics.guardrails?.authorization_denied_events ?? 0;
}

function renderCases() {
  const list = $("case-list");
  const cases = state.persona === "manager_grc"
    ? state.managerQueue
    : state.persona === "legal_privacy"
      ? state.healthcareQueue
      : state.cases;

  if (!cases.length) {
    list.innerHTML = `<div class="empty">No matching cases.</div>`;
    return;
  }

  list.innerHTML = cases
    .map((item) => {
      const active = item.case_id === state.selectedCaseId ? " active" : "";
      const severity = item.triage?.severity || "none";
      const determination = item.triage?.determination || item.triage_status;
      return `
        <button class="case-card${active}" type="button" data-case-id="${escapeHtml(item.case_id)}">
          <p class="case-title">${escapeHtml(item.title)}</p>
          <div class="badge-row">
            <span class="badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span>
            <span class="badge">${escapeHtml(determination)}</span>
          </div>
          <div class="meta-row muted">
            <span>${escapeHtml(item.source_case_id)}</span>
            <span>${escapeHtml(item.triage_status)}</span>
          </div>
        </button>
      `;
    })
    .join("");
}

function renderDetail() {
  const detail = $("case-detail");
  if (!state.selectedCaseId || !state.detail) {
    $("detail-title").textContent = "Select a case";
    detail.innerHTML = `<div class="empty">Case details will appear here.</div>`;
    return;
  }

  $("detail-title").textContent = state.detail.title || state.selectedCaseId;
  $("detail-eyebrow").textContent = state.selectedCaseId;
  const report = state.detail.latest_report || state.detail.report || {};
  detail.innerHTML = `
    <article class="detail-card">
      <div class="badge-row">
        <span class="badge">${escapeHtml(state.detail.status || "case")}</span>
        <span class="badge">${escapeHtml(state.detail.triage_status || "triage")}</span>
        <span class="badge">${escapeHtml(state.detail.role_view?.role || profile().role)}</span>
      </div>
      <div class="kv-grid">
        <div class="kv"><span>Determination</span><strong>${escapeHtml(report.determination || "pending")}</strong></div>
        <div class="kv"><span>Severity</span><strong>${escapeHtml(report.severity || "pending")}</strong></div>
        <div class="kv"><span>Disposition</span><strong>${escapeHtml(report.disposition || "pending")}</strong></div>
        <div class="kv"><span>Confidence</span><strong>${formatConfidence(report.confidence)}</strong></div>
      </div>
    </article>
    ${renderPersonaDetail()}
  `;
}

function renderPersonaDetail() {
  if (state.persona === "manager_grc") {
    return listCard("GRC mappings", state.grc?.items, (item) =>
      `${item.control_category || "control"}: ${item.language_note || "review required"}`);
  }
  if (state.persona === "legal_privacy") {
    return listCard("Healthcare review evidence", state.evidence?.items, (item) =>
      item.summary || item.evidence_id || "evidence item");
  }
  if (state.persona === "audit_debug") {
    return listCard("Audit events", state.audit?.items, (item) =>
      `${item.event_type || "event"}: ${item.summary || item.audit_event_id}`);
  }
  if (state.persona === "engineer") {
    return [
      listCard("Timeline", state.timeline?.items, (item) => `${item.event_type || "event"}: ${item.description || item.evidence_id}`),
      listCard("MITRE mappings", state.mitre?.items, (item) => `${item.technique_id || "technique"}: ${item.technique_name || "mapping"}`),
    ].join("");
  }
  return listCard("Evidence", state.evidence?.items, (item) =>
    item.summary || item.evidence_id || "evidence item");
}

function renderInsights() {
  const target = $("persona-insights");
  $("insight-title").textContent = state.persona === "csi_rgoi" ? "Cognitive retrieval" : "Review signals";
  if (state.persona === "csi_rgoi") {
    target.innerHTML = renderCsi();
    return;
  }

  const managerCount = state.managerQueue.length;
  const healthcareCount = state.healthcareQueue.length;
  const authDenials = state.metrics?.guardrails?.authorization_denied_events ?? 0;
  target.innerHTML = `
    <article class="insight-card">
      <h3>Role boundary</h3>
      <p class="muted">${escapeHtml(profile().label)} view using ${escapeHtml(profile().credential)}</p>
    </article>
    <article class="insight-card">
      <h3>Queue pressure</h3>
      <div class="kv-grid">
        <div class="kv"><span>Manager</span><strong>${managerCount}</strong></div>
        <div class="kv"><span>Healthcare</span><strong>${healthcareCount}</strong></div>
      </div>
    </article>
    <article class="insight-card">
      <h3>Authorization denials</h3>
      <strong>${authDenials}</strong>
    </article>
  `;
}

function renderCsi() {
  const items = state.csi?.items || [];
  if (state.csi?.error) {
    return `<div class="empty error">${escapeHtml(state.csi.error)}</div>`;
  }
  if (!items.length) {
    return `<div class="empty">No cognitive objects visible for this role and purpose.</div>`;
  }
  return items
    .map((item) => {
      const object = item.object || {};
      const trust = item.trust || {};
      return `
        <article class="insight-card">
          <h3>${escapeHtml(object.title || object.id)}</h3>
          <div class="badge-row">
            <span class="badge">${escapeHtml(item.authority_state || "authority")}</span>
            <span class="badge">${escapeHtml(object.retrieval_zone || "zone")}</span>
          </div>
          <div class="kv-grid">
            <div class="kv"><span>Trust</span><strong>${formatConfidence(trust.overall)}</strong></div>
            <div class="kv"><span>Review</span><strong>${escapeHtml(object.review_status || "unknown")}</strong></div>
          </div>
        </article>
      `;
    })
    .join("");
}

function listCard(title, items, mapper) {
  const rows = items || [];
  if (!rows.length) {
    return `<article class="detail-card"><h3>${escapeHtml(title)}</h3><p class="muted">No records.</p></article>`;
  }
  return `
    <article class="detail-card">
      <h3>${escapeHtml(title)}</h3>
      <ul class="list">
        ${rows.slice(0, 5).map((item) => `<li>${escapeHtml(mapper(item))}</li>`).join("")}
      </ul>
    </article>
  `;
}

function renderLoading() {
  $("case-list").innerHTML = `<div class="empty">Loading dashboard data.</div>`;
}

function renderError(message) {
  $("persona-insights").innerHTML = `<div class="empty error">${escapeHtml(message)}</div>`;
}

function formatConfidence(value) {
  if (typeof value !== "number") {
    return "pending";
  }
  return `${Math.round(value * 100)}%`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.addEventListener("click", async (event) => {
  const roleButton = event.target.closest(".role-button");
  if (roleButton) {
    state.persona = roleButton.dataset.persona;
    state.selectedCaseId = null;
    await refreshDashboard();
    return;
  }

  const caseButton = event.target.closest(".case-card");
  if (caseButton) {
    state.selectedCaseId = caseButton.dataset.caseId;
    await refreshDetail();
    render();
  }
});

$("refresh").addEventListener("click", refreshDashboard);
$("seed-case").addEventListener("click", seedCase);
$("status-filter").addEventListener("change", refreshDashboard);
$("severity-filter").addEventListener("change", refreshDashboard);

refreshDashboard();
