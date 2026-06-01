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

const PERSONA_TAB_IDS = {
  analyst: "tab-analyst",
  manager_grc: "tab-manager-grc",
  legal_privacy: "tab-legal-privacy",
  audit_debug: "tab-audit-debug",
  engineer: "tab-engineer",
  csi_rgoi: "tab-csi-rgoi",
};

const REQUEST_TIMEOUT_MS = 8000;

// Personas that authenticate as a case-working role (their demo key maps to
// analyst/engineer) — only these see the assign/release/feedback controls. Other
// personas would be denied (403) by the API anyway.
const ASSIGNABLE_PERSONAS = new Set(["analyst", "engineer"]);
const isAssignable = () => ASSIGNABLE_PERSONAS.has(state.persona);

const API_ROUTES = {
  health: "/health",
  metrics: "/metrics",
  cases: "/cases/read-model",
  myCases: "/queues/my-cases",
  managerQueue: "/queues/manager-review",
  healthcareQueue: "/queues/healthcare-review",
  assign: "/cases/{case_id}/assign",
  release: "/cases/{case_id}/release",
  feedback: "/cases/{case_id}/analyst-feedback",
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
  myCasesOnly: false,
  actionError: null,
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

function sameOriginUrl(path) {
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin) {
    throw new Error("Blocked non-same-origin dashboard request.");
  }
  return url;
}

function withRole(path, params = {}, includeRole = true) {
  const url = sameOriginUrl(path);
  Object.entries(params).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") {
      url.searchParams.set(key, value);
    }
  });
  if (includeRole && !url.searchParams.has("role")) {
    url.searchParams.set("role", profile().role);
  }
  return `${url.pathname}${url.search}`;
}

async function dashboardFetch(path, options = {}) {
  const {
    params = {},
    method = "GET",
    body = null,
    auth = true,
  } = options;
  const requestPath = method === "GET"
    ? withRole(path, params, auth)
    : `${sameOriginUrl(path).pathname}${sameOriginUrl(path).search}`;
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(requestPath, {
      method,
      headers: auth ? headers() : { Accept: "application/json" },
      body: body === null ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    return response.json();
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("Dashboard request timed out.");
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function apiGet(path, params = {}) {
  return dashboardFetch(path, { params });
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
    const casesRequest = state.myCasesOnly && isAssignable()
      ? apiGet(API_ROUTES.myCases, { limit: 25 })
      : apiGet(API_ROUTES.cases, caseFilters());
    const [health, metrics, cases, managerQueue, healthcareQueue, csi] = await Promise.all([
      dashboardFetch(API_ROUTES.health, { auth: false }),
      apiGet(API_ROUTES.metrics),
      casesRequest,
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
    const accepted = await dashboardFetch("/cases", { method: "POST", body: payload });
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
    const isActive = button.dataset.persona === state.persona;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", String(isActive));
    button.setAttribute("tabindex", isActive ? "0" : "-1");
  });
  $("main").setAttribute("aria-labelledby", PERSONA_TAB_IDS[state.persona]);
  $("queue-title").textContent = profile().queueTitle;
  $("active-persona").textContent = profile().label;
  $("my-cases-label").hidden = !isAssignable();
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
  list.setAttribute("aria-busy", "false");
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
    ${renderCopilot()}
    ${renderPersonaDetail()}
  `;
}

function renderCopilot() {
  // The live co-pilot loop (Evolution 3): self-assign -> review -> submit feedback
  // -> release. Only for assignable personas; their demo key IS the authenticated
  // identity, so the API authorizes/attributes correctly per persona.
  if (!isAssignable() || !state.detail) {
    return "";
  }
  const assignedTo = state.detail.assigned_to;
  const ownership = assignedTo
    ? `Assigned to <strong>${escapeHtml(assignedTo)}</strong>`
    : `<span class="muted">Unassigned</span>`;
  const error = state.actionError
    ? `<p class="empty error">${escapeHtml(state.actionError)}</p>`
    : "";
  return `
    <article class="detail-card copilot">
      <h3>Analyst co-pilot</h3>
      <div class="ownership-row">
        <span>${ownership}</span>
        <div class="button-row">
          <button class="command secondary" type="button" data-action="assign">Assign to me</button>
          <button class="command secondary" type="button" data-action="release">Release</button>
        </div>
      </div>
      <div class="feedback-form">
        <div class="field-grid">
          <label>Determination
            <select id="fb-determination">
              <option value="benign">benign</option>
              <option value="suspicious">suspicious</option>
              <option value="malicious">malicious</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label>Severity
            <select id="fb-severity">
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </label>
          <label>Disposition
            <select id="fb-disposition">
              <option value="monitor">monitor</option>
              <option value="close">close</option>
              <option value="escalate">escalate</option>
              <option value="needs_more_info">needs_more_info</option>
            </select>
          </label>
          <label>Confidence
            <input type="number" id="fb-confidence" min="0" max="1" step="0.05" value="0.7" />
          </label>
        </div>
        <label>Notes
          <input type="text" id="fb-notes" placeholder="Optional analyst note (no secrets/PHI)" />
        </label>
        <div class="button-row">
          <button class="command" type="button" data-action="submit-feedback">Submit feedback</button>
        </div>
      </div>
      ${error}
    </article>
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
  $("case-list").setAttribute("aria-busy", "true");
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
    await activatePersona(roleButton.dataset.persona);
    return;
  }

  const actionButton = event.target.closest("[data-action]");
  if (actionButton) {
    await runCaseAction(actionButton.dataset.action);
    return;
  }

  const caseButton = event.target.closest(".case-card");
  if (caseButton) {
    state.selectedCaseId = caseButton.dataset.caseId;
    state.actionError = null;
    await refreshDetail();
    render();
  }
});

async function runCaseAction(action) {
  const caseId = state.selectedCaseId;
  if (!caseId) {
    return;
  }
  state.actionError = null;
  try {
    if (action === "assign") {
      await dashboardFetch(API_ROUTES.assign.replace("{case_id}", caseId), { method: "POST" });
    } else if (action === "release") {
      await dashboardFetch(API_ROUTES.release.replace("{case_id}", caseId), { method: "POST" });
    } else if (action === "submit-feedback") {
      const confidence = Math.min(1, Math.max(0, Number($("fb-confidence").value) || 0.7));
      const body = {
        analyst_id: profile().role,  // server overrides with the authenticated identity
        analyst_determination: $("fb-determination").value,
        analyst_severity: $("fb-severity").value,
        analyst_final_disposition: $("fb-disposition").value,
        analyst_confidence: confidence,
        analyst_notes: $("fb-notes").value || null,
      };
      await dashboardFetch(API_ROUTES.feedback.replace("{case_id}", caseId), { method: "POST", body });
    } else {
      return;
    }
    await refreshDashboard();  // re-fetch list + detail, then render
  } catch (error) {
    state.actionError = error.message;
    render();
  }
}

document.addEventListener("keydown", async (event) => {
  const roleButton = event.target.closest(".role-button");
  if (!roleButton) {
    return;
  }
  const buttons = Array.from(document.querySelectorAll(".role-button"));
  const currentIndex = buttons.indexOf(roleButton);
  let nextIndex = currentIndex;
  if (event.key === "ArrowRight" || event.key === "ArrowDown") {
    nextIndex = (currentIndex + 1) % buttons.length;
  } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
    nextIndex = (currentIndex - 1 + buttons.length) % buttons.length;
  } else if (event.key === "Home") {
    nextIndex = 0;
  } else if (event.key === "End") {
    nextIndex = buttons.length - 1;
  } else {
    return;
  }
  event.preventDefault();
  buttons[nextIndex].focus();
  await activatePersona(buttons[nextIndex].dataset.persona);
});

async function activatePersona(persona) {
  if (state.persona === persona) {
    renderRoleControls();
    return;
  }
  state.persona = persona;
  state.selectedCaseId = null;
  await refreshDashboard();
}

$("refresh").addEventListener("click", refreshDashboard);
$("seed-case").addEventListener("click", seedCase);
$("status-filter").addEventListener("change", refreshDashboard);
$("severity-filter").addEventListener("change", refreshDashboard);
$("my-cases-toggle").addEventListener("change", (event) => {
  state.myCasesOnly = event.target.checked;
  state.selectedCaseId = null;
  refreshDashboard();
});

refreshDashboard();
