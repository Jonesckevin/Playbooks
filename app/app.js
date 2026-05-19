const LIBRARY_MANIFEST = "playbooks/manifest.json";
const LIBRARY_ROOT = "playbooks";
const API_LOAD = "cgi-bin/load_playbooks.sh";
const API_SAVE = "cgi-bin/save_playbook.sh";
const API_UPDATE = "cgi-bin/update_playbook.sh";
const API_DELETE = "cgi-bin/delete_playbook.sh";
const MITRE_TECHNIQUES_URL = "playbooks/mitre-techniques.json";
const NAVIGATOR_APP_URL = "attack-navigator/index.html";
const DEFAULT_TOOL_FALLBACK = "security_onion";
let DEFAULT_TOOL = DEFAULT_TOOL_FALLBACK;

// Full registry of all supported tools/SIEMs
const ALL_TOOLS = {
  splunk:       { label: "Splunk SPL",           lang: "language-bash" },
  kql:          { label: "Microsoft KQL",         lang: "language-sql"  },
  security_onion: { label: "Security Onion",      lang: "language-sql"  },
  qradar:       { label: "IBM QRadar AQL",        lang: "language-sql"  },
  sigma:        { label: "Sigma Rule",            lang: "language-yaml" },
  sysmon:       { label: "Sysmon XML",            lang: "language-xml"  },
  velociraptor: { label: "Velociraptor VQL",      lang: "language-sql"  },
  osquery:      { label: "OSQuery SQL",           lang: "language-sql"  },
  carbon_black: { label: "Carbon Black",          lang: "language-sql"  },
  elastic:      { label: "Elastic EQL",           lang: "language-json" },
  chronicle:    { label: "Google Chronicle",      lang: "language-yaml" },
  crowdstrike:  { label: "CrowdStrike FQL",       lang: "language-bash" },
  defender:     { label: "Defender XDR KQL",      lang: "language-sql"  },
  opensearch:   { label: "OpenSearch DSL",        lang: "language-json" },
  logrhythm:    { label: "LogRhythm Axiom",       lang: "language-sql"  },
};
const TOOL_ORDER  = Object.keys(ALL_TOOLS);
const TOOL_LABELS = Object.fromEntries(Object.entries(ALL_TOOLS).map(([k, v]) => [k, v.label]));
const ATTACK_DOMAIN_LABELS = {
  "enterprise-attack": "Enterprise ATT&CK",
  "mobile-attack": "Mobile ATT&CK",
  "ics-attack": "ICS ATT&CK"
};

const state = {
  manifest: [],
  libraryById: new Map(),
  customById: new Map(),
  allPlaybooks: [],
  selectedId: null,
  activeCardFilter: "all",
  activeCardSearch: "",
  editingId: null,
  mitreTags: [],
  mitreLookup: new Map(),
  mitreIndex: [],
  navigatorLayerObjectUrl: null,
  navigatorLastLayer: null,
  activeCardSevFilter: "all",
  activeSourceFilter: "all",
  checklistEnabled: false,
  activeTools: ["security_onion", "sysmon", "osquery", "velociraptor", "elastic", "carbon_black"],
};

function toggleMobileNav() {
  const open = document.body.classList.toggle("nav-open");
  const btn = document.getElementById("mobile-nav-toggle");
  if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
}

function closeMobileNav() {
  document.body.classList.remove("nav-open");
  const btn = document.getElementById("mobile-nav-toggle");
  if (btn) btn.setAttribute("aria-expanded", "false");
}

function isMobileViewport() {
  return window.matchMedia("(max-width: 980px)").matches;
}

const esc = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#39;");

function toSlug(input) {
  return String(input ?? "").toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
}

function getPlaybookById(id) {
  return state.libraryById.get(id) || state.customById.get(id);
}

const SEV_MAP = {
  critical: { label: "Critical", badge: "b-red" },
  high:     { label: "High",     badge: "b-amber" },
  medium:   { label: "Medium",   badge: "b-blue" },
  low:      { label: "Low",      badge: "b-green" },
};
const humanSev      = sev => SEV_MAP[String(sev ?? "").toLowerCase()]?.label || "Unknown";
const sevBadgeClass = sev => SEV_MAP[String(sev ?? "").toLowerCase()]?.badge || "b-green";

function computeCompleteness(pb) {
  const tools = state.activeTools;
  const result = {};
  const allSteps = [
    ...(pb.investigation?.detectionAnalysis || []),
    ...(pb.investigation?.containment || []),
    ...(pb.investigation?.eradication || []),
    ...(pb.investigation?.recovery || [])
  ];
  for (const tool of tools) {
    result[tool] = allSteps.some(s => s.queries && s.queries[tool] != null);
  }
  return result;
}

function splitMitre(value) {
  if (Array.isArray(value)) {
    return [...new Set(value.filter(Boolean).map((v) => normalizeMitreId(String(v))).filter(Boolean))];
  }
  if (!value) return [];
  return [...new Set(String(value).split(",").map((v) => normalizeMitreId(v)).filter(Boolean))];
}

function normalizeMitreId(value) {
  const id = String(value || "").trim().toUpperCase();
  if (!id) return "";
  const match = id.match(/^T\d{4}(?:\.\d{3})?$/);
  return match ? match[0] : "";
}

function mitreFallbackUrl(id) {
  const parts = id.split(".");
  return parts.length === 2
    ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
    : `https://attack.mitre.org/techniques/${parts[0]}/`;
}

function getMitreTechniqueInfo(rawId) {
  const id = normalizeMitreId(rawId) || String(rawId || "").trim().toUpperCase();
  if (!id) return null;
  const found = state.mitreLookup.get(id);
  return {
    id,
    name: found?.name || "",
    url: found?.url || mitreFallbackUrl(id),
    domains: Array.isArray(found?.domains) ? found.domains : []
  };
}

function renderMitreLink(rawId, includeName = false) {
  const info = getMitreTechniqueInfo(rawId);
  if (!info) return "";
  const label = includeName && info.name ? `${info.id} - ${info.name}` : info.id;
  const title = info.name ? `${info.id}: ${info.name}` : info.id;
  return `<a class="mitre mitre-link" href="${esc(info.url)}" target="_blank" rel="noopener noreferrer" title="${esc(title)}">${esc(label)}</a>`;
}

async function loadMitreTechniques() {
  state.mitreLookup.clear();
  state.mitreIndex = [];
  const payload = await fetchJson(MITRE_TECHNIQUES_URL).catch(() => null);
  if (!payload || !Array.isArray(payload.techniques)) return;

  for (const item of payload.techniques) {
    const id = normalizeMitreId(item?.id);
    if (!id) continue;
    const record = {
      id,
      name: String(item?.name || id),
      url: String(item?.url || mitreFallbackUrl(id)),
      domains: Array.isArray(item?.domains) ? item.domains.map((d) => String(d).toLowerCase()) : []
    };
    state.mitreLookup.set(id, record);
    state.mitreIndex.push(record);
  }
}

function collectTechniqueCoverage(playbooks) {
  const coverage = new Map();
  for (const pb of playbooks) {
    const ids = splitMitre(pb?.mitre || []);
    for (const id of ids) {
      const entry = coverage.get(id) || { count: 0, playbooks: new Set() };
      entry.count += 1;
      entry.playbooks.add(pb.name || pb.id || "Unknown");
      coverage.set(id, entry);
    }
  }
  return coverage;
}

function buildNavigatorLayer(playbooks, attackDomain) {
  const domainKey = attackDomain.split("-")[0];
  const coverage = collectTechniqueCoverage(playbooks);
  const techniques = [];

  for (const [id, info] of coverage.entries()) {
    const technique = getMitreTechniqueInfo(id);
    const domains = technique?.domains?.length ? technique.domains : ["enterprise"];
    if (!domains.includes(domainKey)) continue;

    const names = Array.from(info.playbooks).sort((a, b) => a.localeCompare(b));
    const preview = names.slice(0, 6).join(", ");
    const extra = names.length > 6 ? ` (+${names.length - 6} more)` : "";

    techniques.push({
      techniqueID: id,
      score: info.count,
      comment: `Monitored in ${names.length} playbook(s): ${preview}${extra}`,
      metadata: [
        { name: "Playbook Count", value: String(info.count) },
        { name: "Playbooks", value: names.join(", ") }
      ]
    });
  }

  techniques.sort((a, b) => a.techniqueID.localeCompare(b.techniqueID, undefined, { numeric: true }));
  const maxScore = techniques.reduce((max, t) => Math.max(max, t.score || 0), 1);

  return {
    name: `SOC Coverage - ${ATTACK_DOMAIN_LABELS[attackDomain] || attackDomain}`,
    versions: {
      attack: "17",
      navigator: "5.3.2",
      layer: "4.5"
    },
    domain: attackDomain,
    description: "Techniques referenced by playbook MITRE selections (monitored coverage view).",
    sorting: 0,
    hideDisabled: false,
    gradient: {
      colors: ["#e6f1fb", "#185fa5"],
      minValue: 1,
      maxValue: maxScore
    },
    techniques
  };
}

function revokeNavigatorLayerUrl() {
  if (state.navigatorLayerObjectUrl) {
    URL.revokeObjectURL(state.navigatorLayerObjectUrl);
    state.navigatorLayerObjectUrl = null;
  }
}

function applyNavigatorLightTheme(frame) {
  try {
    const doc = frame?.contentDocument || frame?.contentWindow?.document;
    if (!doc) return;

    const themeHost = doc.querySelector(".theme-use-system, .theme-override-dark, .theme-override-light");
    if (themeHost) {
      themeHost.classList.remove("theme-use-system", "theme-override-dark", "theme-override-light");
      themeHost.classList.add("theme-override-light");
    }

    let style = doc.getElementById("playbooks-nav-light-theme");
    if (!style) {
      style = doc.createElement("style");
      style.id = "playbooks-nav-light-theme";
      style.textContent = [
        ".theme-override-light { color-scheme: light !important; }",
        ".theme-override-light .mat-mdc-tab-nav-bar, .theme-override-light .controlsContainer { box-shadow: none !important; }",
        ".theme-override-light .controlsContainer .control-sections > li .control-row-item .control-row-button:hover { background-color: #d7e8fa !important; }",
        ".theme-override-light a { color: #185fa5 !important; }"
      ].join("\n");
      doc.head.appendChild(style);
    }
  } catch (err) {
    console.warn("Navigator light theme override failed:", err);
  }
}

function updateNavigatorLayer() {
  const playbookSelect = document.getElementById("navigator-playbook-select");
  const domainSelect = document.getElementById("navigator-domain-select");
  const summary = document.getElementById("navigator-summary");
  const frame = document.getElementById("navigator-iframe");
  if (!playbookSelect || !domainSelect || !summary || !frame) return;

  const selectedId = playbookSelect.value;
  const selectedPlaybooks = selectedId === "all"
    ? [...state.allPlaybooks]
    : state.allPlaybooks.filter((pb) => pb.id === selectedId);
  const domain = domainSelect.value;

  const layer = buildNavigatorLayer(selectedPlaybooks, domain);
  state.navigatorLastLayer = layer;

  revokeNavigatorLayerUrl();
  state.navigatorLayerObjectUrl = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" }));
  frame.onload = () => {
    applyNavigatorLightTheme(frame);
    setTimeout(() => applyNavigatorLightTheme(frame), 120);
    setTimeout(() => applyNavigatorLightTheme(frame), 500);
  };
  frame.src = `${NAVIGATOR_APP_URL}#layerURL=${encodeURIComponent(state.navigatorLayerObjectUrl)}`;

  summary.textContent = `${layer.techniques.length} technique(s) mapped from ${selectedPlaybooks.length} playbook(s) in ${ATTACK_DOMAIN_LABELS[domain] || domain}.`;
}

function downloadNavigatorLayer() {
  if (!state.navigatorLastLayer) return;
  const domain = state.navigatorLastLayer.domain || "enterprise-attack";
  const fileName = `mitre-monitored-${domain}.json`;
  const href = URL.createObjectURL(new Blob([JSON.stringify(state.navigatorLastLayer, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = href;
  a.download = fileName;
  a.click();
  URL.revokeObjectURL(href);
}

function openNavigatorInNewTab() {
  if (!state.navigatorLayerObjectUrl) return;
  window.open(`${NAVIGATOR_APP_URL}#layerURL=${encodeURIComponent(state.navigatorLayerObjectUrl)}`, "_blank", "noopener,noreferrer");
}

function renderNavigatorPanel() {
  const root = document.getElementById("navigator-root");
  if (!root) return;

  const prevPlaybook = document.getElementById("navigator-playbook-select")?.value || "all";
  const prevDomain = document.getElementById("navigator-domain-select")?.value || "enterprise-attack";

  const options = [`<option value="all">All playbooks</option>`]
    .concat(state.allPlaybooks.map((pb) => `<option value="${esc(pb.id)}">#${pb.num || "-"} ${esc(pb.name)}</option>`))
    .join("");

  root.innerHTML = `
    <div class="navigator-panel">
      <div class="navigator-controls">
        <div class="navigator-field">
          <label for="navigator-playbook-select">Coverage source</label>
          <select class="navigator-select" id="navigator-playbook-select" onchange="updateNavigatorLayer()">${options}</select>
        </div>
        <div class="navigator-field">
          <label for="navigator-domain-select">ATT&CK domain</label>
          <select class="navigator-select" id="navigator-domain-select" onchange="updateNavigatorLayer()">
            <option value="enterprise-attack">Enterprise ATT&CK</option>
            <option value="mobile-attack">Mobile ATT&CK</option>
            <option value="ics-attack">ICS ATT&CK</option>
          </select>
        </div>
        <button class="btn btn-secondary" onclick="downloadNavigatorLayer()">Download layer</button>
        <button class="btn btn-secondary" onclick="openNavigatorInNewTab()">Open in new tab</button>
      </div>
      <div class="navigator-summary" id="navigator-summary"></div>
      <iframe id="navigator-iframe" class="navigator-embed" title="MITRE ATT&CK Navigator"></iframe>
    </div>
  `;

  const playbookSelect = document.getElementById("navigator-playbook-select");
  const domainSelect = document.getElementById("navigator-domain-select");
  if (playbookSelect && playbookSelect.querySelector(`option[value="${CSS.escape(prevPlaybook)}"]`)) {
    playbookSelect.value = prevPlaybook;
  }
  if (domainSelect && domainSelect.querySelector(`option[value="${CSS.escape(prevDomain)}"]`)) {
    domainSelect.value = prevDomain;
  }

  updateNavigatorLayer();
}

function normalizeSteps(source) {
  if (!Array.isArray(source)) return [];
  return source.map((step, idx) => {
    if (typeof step === "string") {
      return { title: step, detail: "", queries: {} };
    }
    const queries = {};
    for (const tool of TOOL_ORDER) {
      const raw = step?.queries?.[tool] ?? step?.[tool] ?? "";
      if (raw) queries[tool] = String(raw);
    }
    return {
      n: step?.n ?? idx + 1,
      title: String(step?.title ?? "").trim(),
      detail: String(step?.detail ?? "").trim(),
      queries
    };
  }).filter((s) => s.title || s.detail || Object.keys(s.queries).length > 0);
}

function normalizePlaybook(pb) {
  const mitre = splitMitre(pb.mitre);
  const investigation = pb.investigation || {};
  const detectionSource = investigation.detectionAnalysis || investigation.detection || pb.detSteps || [];
  const containmentSource = investigation.containment || pb.contSteps || [];
  const eradicationSource = investigation.eradication || pb.eradSteps || [];
  const recoverySource = investigation.recovery || investigation.lessonsLearned || pb.recSteps || [];
  return {
    id: pb.id,
    num: pb.num ?? 0,
    name: pb.name || "Untitled",
    cat: pb.cat || "Other",
    sev: (pb.sev || "medium").toLowerCase(),
    type: pb.type || pb.cat || "Other",
    source: pb.source || "library",
    scenario: pb.scenario || "",
    detection: pb.detection || "",
    mitre,
    splunk: pb.splunk || "",          // legacy field (kept for backward compat)
    primaryQuery: pb.primaryQuery || pb.splunk || "",
    createdAt: pb.createdAt || "",
    investigation: {
      detectionAnalysis: normalizeSteps(detectionSource),
      containment: normalizeSteps(containmentSource),
      eradication: normalizeSteps(eradicationSource),
      recovery: normalizeSteps(recoverySource)
    },
    updated: pb.updated || "",
    related: Array.isArray(pb.related) ? pb.related : []
  };
}

async function fetchJson(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return res.json();
}

async function loadManifest() {
  const data = await fetchJson(LIBRARY_MANIFEST);
  state.manifest = Array.isArray(data.playbooks) ? data.playbooks : [];
}

async function loadLibraryDetails() {
  const tasks = state.manifest.map(async (item) => {
    const data = await fetchJson(`${LIBRARY_ROOT}/${item.file}`);
    const merged = normalizePlaybook({ ...item, ...data, source: "library" });
    state.libraryById.set(merged.id, merged);
  });
  await Promise.all(tasks);
}

async function loadCustomPlaybooks() {
  state.customById.clear();
  const payload = await fetchJson(API_LOAD).catch(() => []);
  if (!Array.isArray(payload)) return;
  for (const raw of payload) {
    if (!raw?.id) continue;
    const item = normalizePlaybook(raw);
    state.customById.set(item.id, item);
  }
}

function buildMergedPlaybooks() {
  const merged = new Map(state.libraryById);
  for (const [id, custom] of state.customById.entries()) {
    const hasLibraryBase = merged.has(id);
    merged.set(id, {
      ...merged.get(id),
      ...custom,
      id,
      source: hasLibraryBase ? "library-override" : "custom"
    });
  }
  state.allPlaybooks = Array.from(merged.values()).sort((a, b) => (a.num || 0) - (b.num || 0));
}

function groupedByCategory() {
  const groups = new Map();
  for (const pb of state.allPlaybooks) {
    const key = pb.cat || "Other";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(pb);
  }
  return Array.from(groups.entries()).sort((a, b) => a[0].localeCompare(b[0]));
}

function renderSidebar() {
  const host = document.getElementById("dyn-nav");
  if (!host) return;

  const groups = groupedByCategory();
  host.innerHTML = groups.map(([cat, items]) => {
    const groupId = `g-${toSlug(cat) || "other"}`;
    const color = items[0]?.sev === "critical" ? "#a32d2d" : items[0]?.sev === "high" ? "#854f0b" : items[0]?.sev === "medium" ? "#185fa5" : "#3b6d11";
    const nav = items.map((pb) => `
      <div class="nav-item" data-title="${esc(pb.name)}" data-cat="${esc(pb.cat)}" id="nav-${esc(pb.id)}" onclick="openPlaybook('${esc(pb.id)}', this)">
        <span class="dot d-${pb.sev === "critical" ? "crit" : pb.sev === "high" ? "high" : pb.sev === "medium" ? "med" : "low"}"></span>${esc(pb.name)}
      </div>
    `).join("");
    return `
      <div class="sb-section" style="--cat-clr:${color}">
        <div class="sb-group-header" onclick="toggleGroup('${groupId}')">
          <span class="sb-group-label">${esc(cat)}</span>
          <span class="sb-group-meta"><span class="sb-group-count">${items.length}</span><span class="sb-group-arr" id="${groupId}-arr">▾</span></span>
        </div>
        <div class="nav-group" id="${groupId}">${nav}</div>
      </div>
    `;
  }).join("");
}

function updateCardCount() {
  const badge = document.getElementById("pb-count-badge");
  if (badge) badge.textContent = `${state.allPlaybooks.length} playbooks`;
}

function renderCards() {
  const host = document.getElementById("cards-grid");
  if (!host) return;

  const search = state.activeCardSearch.trim().toLowerCase();
  host.innerHTML = state.allPlaybooks.map((pb) => {
    const haystack = [pb.name, pb.cat, pb.type, pb.mitre.join(" ")].join(" ").toLowerCase();
    const catOk    = state.activeCardFilter === "all" || pb.cat === state.activeCardFilter;
    const sevOk    = state.activeCardSevFilter === "all" || pb.sev === state.activeCardSevFilter;
    const sourceOk = state.activeSourceFilter === "all" ||
                     (state.activeSourceFilter === "custom"  && (pb.source === "custom" || pb.source === "library-override")) ||
                     (state.activeSourceFilter === "library" && pb.source === "library");
    const searchOk = !search || haystack.includes(search);
    const hidden = !catOk || !sevOk || !sourceOk || !searchOk;
    const mitreBadges = pb.mitre.slice(0, 3).map((m) => `<span class="mitre">${esc(m)}</span>`).join("");
    const comp = computeCompleteness(pb);
    const pipsHtml = `<div class="card-completeness">${state.activeTools.map(t =>
      `<span class="tool-pip tool-pip-${t} ${comp[t] ? 'pip-on' : 'pip-off'}" title="${TOOL_LABELS[t] || t}"></span>`
    ).join('')}</div>`;
    const updatedHtml = pb.updated ? `<div class="card-updated">Updated ${pb.updated}</div>` : '';
    return `
      <div class="card ${hidden ? "hidden" : ""}" data-cat="${esc(pb.cat)}" onclick="openPlaybook('${esc(pb.id)}')">
        <div class="card-num">#${pb.num || "-"}</div>
        <div class="card-name">${esc(pb.name)}</div>
        <div class="card-badges">
          <span class="badge ${sevBadgeClass(pb.sev)}">${humanSev(pb.sev)}</span>
          <span class="badge b-gray">${esc(pb.cat)}</span>
          ${pb.source === "custom" ? '<span class="badge b-purple">Custom</span>' : ""}
          ${mitreBadges}
        </div>
        ${pipsHtml}
        ${updatedHtml}
      </div>
    `;
  }).join("");
}

function stepToHtml(step, idx, activeTool, pbId, checklistEnabled, checklist, globalIdx) {
  const q = step.queries?.[activeTool] || "";
  const qLabelClass = `step-q-label--${activeTool}`;
  const qClass = q ? "" : "step-q--empty";
  const codeClass = ALL_TOOLS[activeTool]?.lang || "language-plaintext";
  const sigmaState = activeTool === "sigma" ? validateSigma(q) : null;
  const sigmaBadge = sigmaState ? `<span class="badge ${sigmaState.ok ? "b-green" : "b-red"}" style="margin-left:8px">${sigmaState.ok ? "Valid Sigma" : sigmaState.reason}</span>` : "";

  const checked = checklistEnabled && checklist && checklist[globalIdx];
  const wrapOpen = checklistEnabled ? `<div class="step-checklist${checked ? ' step-checked' : ''}"><input type="checkbox" class="step-check" ${checked ? 'checked' : ''} onchange="toggleChecklistStep('${pbId}',${globalIdx},this.checked)"><div class="step-body">` : '';
  const wrapClose = checklistEnabled ? '</div></div>' : '';

  const stepContent = `
    <div class="step">
      <div class="step-n">${idx + 1}</div>
      <div>
        <div class="step-t">${esc(step.title || "Untitled step")}</div>
        ${step.detail ? `<div class="step-d">${esc(step.detail)}</div>` : ""}
        <div class="step-q ${qClass}">
          <span class="step-q-label ${qLabelClass}">${esc(TOOL_LABELS[activeTool])}${sigmaBadge}</span>
          ${q ? `<pre><code class="${codeClass}">${esc(q)}</code></pre>` : '<div class="no-query-msg">No query defined for this tool on this step.</div>'}
        </div>
      </div>
    </div>
  `;
  return wrapOpen + stepContent + wrapClose;
}

function sectionToHtml(title, steps, activeTool, pbId, checklistEnabled, checklist, offset) {
  if (!steps.length) {
    return `
      <div class="sec">
        <div class="sec-label">${esc(title)}</div>
        <div class="no-steps">No steps defined.</div>
      </div>
    `;
  }
  return `
    <div class="sec">
      <div class="sec-label">${esc(title)}</div>
      <div class="steps">${steps.map((s, i) => stepToHtml(s, i, activeTool, pbId, checklistEnabled, checklist, (offset || 0) + i)).join("")}</div>
    </div>
  `;
}

function renderDetail(playbook, activeTool = DEFAULT_TOOL) {
  const host = document.getElementById("detail-content");
  if (!host) return;

  const tabs = state.activeTools.map((tool) => `<button class="tool-tab ${tool === activeTool ? "active" : ""}" onclick="switchToolTab('${esc(playbook.id)}','${tool}')">${esc(TOOL_LABELS[tool])}</button>`).join("");
  const mitre = playbook.mitre.map((m) => renderMitreLink(m, false)).join("");

  const checklist = loadChecklist(playbook.id);
  const detSteps = playbook.investigation?.detectionAnalysis || [];
  const contSteps = playbook.investigation?.containment || [];
  const eradSteps = playbook.investigation?.eradication || [];
  const recSteps = playbook.investigation?.recovery || [];
  const allSteps = [...detSteps, ...contSteps, ...eradSteps, ...recSteps];
  const totalSteps = allSteps.length;
  const doneSteps = Object.values(checklist).filter(Boolean).length;
  const progressPct = totalSteps > 0 ? Math.round((doneSteps / totalSteps) * 100) : 0;

  const checklistBarHtml = `
    <div class="checklist-bar">
      <button class="checklist-toggle-btn${state.checklistEnabled ? ' active' : ''}" onclick="toggleChecklist('${esc(playbook.id)}')">
        ${state.checklistEnabled ? '✓ Checklist On' : '▷ Start Incident'}
      </button>
      ${state.checklistEnabled ? `
        <div class="checklist-progress-wrap">
          <div class="checklist-progress" style="width:${progressPct}%"></div>
        </div>
        <span class="checklist-done">${doneSteps}/${totalSteps} steps</span>
        <button class="checklist-reset-btn" onclick="resetChecklist('${esc(playbook.id)}')">Reset</button>
      ` : ''}
    </div>`;

  const relatedHtml = (playbook.related && playbook.related.length > 0) ? `
    <div class="related-section">
      <div class="related-label">Related Playbooks</div>
      <div class="related-list">
        ${playbook.related.map(relId => {
          const rel = getPlaybookById(relId);
          return rel ? `<button class="related-chip" onclick="openPlaybook('${relId}')">${esc(rel.name)}</button>` : '';
        }).filter(Boolean).join('')}
      </div>
    </div>` : '';

  const detOffset = 0;
  const contOffset = detSteps.length;
  const eradOffset = contOffset + contSteps.length;
  const recOffset = eradOffset + eradSteps.length;

  host.innerHTML = `
    <div class="pb-ey">${esc(playbook.type || playbook.cat)}</div>
    <div class="pb-ti">${esc(playbook.name)}</div>
    <div class="pb-me">
      <span class="badge ${sevBadgeClass(playbook.sev)}">${humanSev(playbook.sev)}</span>
      <span class="badge b-gray">${esc(playbook.cat)}</span>
      ${playbook.source === "custom" ? '<span class="badge b-purple">Custom</span>' : '<span class="badge b-blue">Library</span>'}
      ${mitre}
    </div>
    <div class="detail-actions">
      <button class="btn btn-secondary" onclick="startEdit('${esc(playbook.id)}')">Edit</button>
      <button class="btn btn-danger" onclick="deletePlaybook('${esc(playbook.id)}')">Delete / Revert</button>
      <button class="btn btn-print" onclick="printPlaybook()">🖨 Print</button>
      <button class="btn btn-soar" onclick="exportSoar('${esc(playbook.id)}')">⬇ Export SOAR</button>
    </div>
    ${checklistBarHtml}
    ${playbook.scenario ? `<div class="scenario-box">${esc(playbook.scenario)}</div>` : ""}
    <div class="tool-tabs-bar">${tabs}</div>
    ${sectionToHtml("Detection & analysis", detSteps, activeTool, playbook.id, state.checklistEnabled, checklist, detOffset)}
    ${sectionToHtml("Containment", contSteps, activeTool, playbook.id, state.checklistEnabled, checklist, contOffset)}
    ${sectionToHtml("Eradication", eradSteps, activeTool, playbook.id, state.checklistEnabled, checklist, eradOffset)}
    ${sectionToHtml("Recovery & lessons learned", recSteps, activeTool, playbook.id, state.checklistEnabled, checklist, recOffset)}
    ${relatedHtml}
  `;

  if (window.hljs) {
    host.querySelectorAll("pre code").forEach((block) => window.hljs.highlightElement(block));
  }
}

function setActiveNav(target) {
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
  document.querySelectorAll(".sb-create-btn").forEach((n) => n.classList.remove("active"));
  if (target) target.classList.add("active");
}

function showPanel(name, navEl) {
  document.querySelectorAll(".panel").forEach((p) => p.classList.remove("visible"));
  const panel = document.getElementById(`panel-${name}`);
  if (panel) panel.classList.add("visible");
  if (navEl) {
    setActiveNav(navEl);
  }
  if (isMobileViewport()) closeMobileNav();
}

function openPlaybook(id, navEl) {
  const pb = state.allPlaybooks.find((p) => p.id === id);
  if (!pb) return;
  state.checklistEnabled = false;
  state.selectedId = id;
  renderDetail(pb, DEFAULT_TOOL);
  showPanel("detail", navEl || document.getElementById(`nav-${id}`));
  if (isMobileViewport()) closeMobileNav();
}

function switchToolTab(id, tool) {
  const pb = state.allPlaybooks.find((p) => p.id === id);
  if (!pb) return;
  renderDetail(pb, tool);
}

function toggleGroup(groupId) {
  const el = document.getElementById(groupId);
  const arr = document.getElementById(`${groupId}-arr`);
  if (!el || !arr) return;
  const hidden = el.style.display === "none";
  el.style.display = hidden ? "block" : "none";
  arr.textContent = hidden ? "▾" : "▸";
}

function searchNav(input) {
  const q = String(input || "").trim().toLowerCase();
  const items = document.querySelectorAll("#sb-nav .nav-item");
  items.forEach((item) => {
    if (item.id === "nav-home" || item.id === "nav-base" || item.id === "nav-create") return;
    const title = (item.dataset.title || item.textContent || "").toLowerCase();
    const cat = (item.dataset.cat || "").toLowerCase();
    item.classList.toggle("hidden", q && !(title.includes(q) || cat.includes(q)));
  });
}

function filterCards(cat, btn) {
  state.activeCardFilter = cat;
  document.querySelectorAll(".filter-btn").forEach((b) => b.classList.remove("on"));
  if (btn) btn.classList.add("on");
  renderCards();
}

function filterSource(src, btn) {
  state.activeSourceFilter = src;
  document.querySelectorAll(".source-filter-btn").forEach(b => b.classList.remove("on"));
  if (btn) btn.classList.add("on");
  renderCards();
}

function filterSourceSelect(val) {
  state.activeSourceFilter = val;
  renderCards();
}

function filterSeveritySelect(val) {
  state.activeCardSevFilter = val;
  renderCards();
}

function filterSeverity(sev, btn) {  state.activeCardSevFilter = sev;
  document.querySelectorAll(".sev-filter-btn").forEach(b => b.classList.remove("on"));
  if (btn) {
    btn.classList.add("on");
  } else {
    const target = document.querySelector(`.sev-filter-btn.sev-${sev}`);
    if (target) target.classList.add("on");
  }
  renderCards();
}

function loadChecklist(pbId) {
  try {
    return JSON.parse(localStorage.getItem(`checklist-${pbId}`) || '{}');
  } catch { return {}; }
}
function saveChecklist(pbId, data) {
  localStorage.setItem(`checklist-${pbId}`, JSON.stringify(data));
}
function toggleChecklist(pbId) {
  const pb = getPlaybookById(pbId);
  if (!pb) return;
  state.checklistEnabled = !state.checklistEnabled;
  renderDetail(pb);
}
function toggleChecklistStep(pbId, stepIdx, checked) {
  const data = loadChecklist(pbId);
  data[stepIdx] = checked;
  saveChecklist(pbId, data);
  const pb = getPlaybookById(pbId);
  if (pb) renderDetail(pb);
}
function resetChecklist(pbId) {
  localStorage.removeItem(`checklist-${pbId}`);
  const pb = getPlaybookById(pbId);
  if (pb) renderDetail(pb);
}
function readStepRows(containerId) {
  const rows = document.querySelectorAll(`#${containerId} .step-row`);
  return Array.from(rows).map((row, idx) => {
    const title = row.querySelector(".step-row-title")?.value?.trim() || "";
    const detail = row.querySelector(".step-row-detail")?.value?.trim() || "";
    const queries = {};
    for (const tool of TOOL_ORDER) {
      const v = row.querySelector(`.step-query-input[data-tool='${tool}']`)?.value?.trim();
      if (v) queries[tool] = v;
    }
    return { n: idx + 1, title, detail, queries };
  }).filter((s) => s.title || s.detail || Object.keys(s.queries).length > 0);
}

function stepRowTemplate(index, step = {}) {
  return `
    <div class="step-row">
      <div class="step-row-n">${index + 1}</div>
      <div class="step-row-body">
        <input class="step-row-title" placeholder="Step title" value="${esc(step.title || "")}">
        <textarea class="step-row-detail" rows="2" placeholder="Step detail">${esc(step.detail || "")}</textarea>
        <details class="step-query-details">
          <summary class="step-query-summary">Tool queries <span class="step-query-hint">(optional)</span></summary>
          <div class="step-query-grid">
            ${TOOL_ORDER.map((tool) => `
              <div class="step-query-field">
                <span class="step-query-label step-query-label--${tool}">${esc(TOOL_LABELS[tool])}</span>
                <textarea class="step-query-input" data-tool="${tool}" rows="2" placeholder="Query for ${esc(TOOL_LABELS[tool])}">${esc(step.queries?.[tool] || "")}</textarea>
              </div>
            `).join("")}
          </div>
        </details>
      </div>
      <div class="step-del" onclick="this.closest('.step-row').remove(); renumberAllSteps()">×</div>
    </div>
  `;
}

function renumberAllSteps() {
  document.querySelectorAll(".step-builder-body").forEach((body) => {
    body.querySelectorAll(".step-row").forEach((row, idx) => {
      const n = row.querySelector(".step-row-n");
      if (n) n.textContent = idx + 1;
    });
  });
}

function addStep(containerId, seed) {
  const body = document.getElementById(containerId);
  if (!body) return;
  const index = body.querySelectorAll(".step-row").length;
  body.insertAdjacentHTML("beforeend", stepRowTemplate(index, seed || {}));
}

function resetBuilder() {
  ["det-steps", "cont-steps", "erad-steps", "rec-steps"].forEach((id) => {
    const body = document.getElementById(id);
    if (body) body.innerHTML = "";
  });
  addStep("det-steps");
}

function addMitreTag() {
  const input = document.querySelector(".mitre-tag-input");
  if (!input) return;
  const value = normalizeMitreId(input.value);
  if (!value) return;
  if (!state.mitreTags.includes(value)) state.mitreTags.push(value);
  input.value = "";
  updateMitreInputHint("");
  renderMitreTags();
}

function removeMitre(tag) {
  state.mitreTags = state.mitreTags.filter((t) => t !== tag);
  renderMitreTags();
}

function renderMitreTags() {
  const host = document.getElementById("mitre-tags-display");
  if (!host) return;
  host.innerHTML = state.mitreTags.map((tag) => {
    const info = getMitreTechniqueInfo(tag);
    const name = info?.name ? `<span class="mitre-chip-name">${esc(info.name)}</span>` : "";
    const link = renderMitreLink(tag, false);
    return `<span class="mitre-chip">${link}${name}<button class="mitre-chip-remove" onclick="removeMitre('${esc(tag)}')" aria-label="Remove ${esc(tag)}">×</button></span>`;
  }).join("");
}

function updateMitreInputHint(value) {
  const hint = document.getElementById("mitre-input-help");
  if (!hint) return;

  const query = String(value || "").trim().toUpperCase();
  if (!query) {
    hint.textContent = "Enter ATT&CK ID (e.g. T1059.001). Click an added tag to open the ATT&CK page.";
    return;
  }

  const exact = state.mitreLookup.get(query);
  if (exact) {
    hint.innerHTML = `Matched: <a href="${esc(exact.url)}" target="_blank" rel="noopener noreferrer">${esc(exact.id)} - ${esc(exact.name)}</a>`;
    return;
  }

  const fuzzy = state.mitreIndex.find((t) => t.id.startsWith(query));
  if (fuzzy) {
    hint.innerHTML = `Suggestion: <a href="${esc(fuzzy.url)}" target="_blank" rel="noopener noreferrer">${esc(fuzzy.id)} - ${esc(fuzzy.name)}</a>`;
    return;
  }

  hint.textContent = "No known ATT&CK technique ID match yet.";
}

function populateMitreDatalist() {
  const list = document.getElementById("mitre-id-suggestions");
  if (!list) return;
  list.innerHTML = state.mitreIndex.map((t) => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join("");
}

function setEditMode(editing, playbook) {
  const eye = document.getElementById("create-eyebrow");
  const title = document.getElementById("create-title");
  const meta = document.getElementById("create-meta");
  const save = document.getElementById("save-playbook-btn");
  const cancel = document.getElementById("cancel-edit-btn");

  if (editing) {
    if (eye) eye.textContent = "Analyst tool";
    if (title) title.textContent = "Edit playbook";
    if (meta) {
      meta.innerHTML = `<span class="badge b-purple">${playbook?.source === "custom" ? "Custom" : "Library override"}</span>`;
    }
    if (save) save.textContent = "Update playbook";
    if (cancel) cancel.style.display = "inline-block";
  } else {
    if (eye) eye.textContent = "Analyst tool";
    if (title) title.textContent = "Create a playbook";
    if (meta) meta.innerHTML = '<span class="badge b-purple">Custom</span>';
    if (save) save.textContent = "Save playbook";
    if (cancel) cancel.style.display = "none";
  }
}

function fillFormFromPlaybook(pb) {
  document.getElementById("f-name").value = pb.name || "";
  document.getElementById("f-scenario").value = pb.scenario || "";
  document.getElementById("f-cat").value = pb.cat || "";
  document.getElementById("f-sev").value = pb.sev || "medium";
  document.getElementById("f-detection").value = pb.detection || "";
  document.getElementById("f-primary-query").value = pb.primaryQuery || pb.splunk || "";

  state.mitreTags = [...pb.mitre];
  renderMitreTags();

  const sections = [
    ["det-steps", pb.investigation.detectionAnalysis],
    ["cont-steps", pb.investigation.containment],
    ["erad-steps", pb.investigation.eradication],
    ["rec-steps", pb.investigation.recovery]
  ];
  for (const [id, steps] of sections) {
    const body = document.getElementById(id);
    if (!body) continue;
    body.innerHTML = "";
    if (!steps.length) {
      addStep(id);
      continue;
    }
    steps.forEach((s) => addStep(id, s));
  }
}

function collectFormPayload() {
  const name = document.getElementById("f-name").value.trim();
  const scenario = document.getElementById("f-scenario").value.trim();
  const cat = document.getElementById("f-cat").value;
  const sev = document.getElementById("f-sev").value;
  const isLibraryEdit = !!state.editingId && state.libraryById.has(state.editingId);

  if (!name || !scenario || !cat) {
    throw new Error("Please complete title, scenario, and category.");
  }

  return {
    name,
    scenario,
    cat,
    sev,
    type: cat,
    source: isLibraryEdit ? "library-override" : "custom",
    detection: document.getElementById("f-detection").value.trim(),
    mitre: [...state.mitreTags],
    primaryQuery: document.getElementById("f-primary-query").value.trim(),
    investigation: {
      detectionAnalysis: readStepRows("det-steps"),
      containment: readStepRows("cont-steps"),
      eradication: readStepRows("erad-steps"),
      recovery: readStepRows("rec-steps")
    }
  };
}

async function savePlaybook() {
  try {
    const payload = collectFormPayload();
    if (state.editingId) payload.id = state.editingId;

    const endpoint = state.editingId ? API_UPDATE : API_SAVE;
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const body = await res.json();
    if (!res.ok || body.error) {
      throw new Error(body.error || "Failed to save playbook");
    }

    const banner = document.getElementById("create-success");
    if (banner) {
      banner.textContent = state.editingId ? "Playbook updated successfully." : "Playbook saved successfully and added to the library.";
      banner.style.display = "block";
      setTimeout(() => { banner.style.display = "none"; }, 2600);
    }

    state.editingId = null;
    setEditMode(false);
    resetForm(false);
    await refreshData();
    showPanel("home", document.getElementById("nav-home"));
  } catch (err) {
    alert(err.message || "Unable to save playbook.");
  }
}

function startEdit(id) {
  const pb = state.allPlaybooks.find((p) => p.id === id);
  if (!pb) return;
  state.editingId = id;
  setEditMode(true, pb);
  fillFormFromPlaybook(pb);
  showPanel("create", document.getElementById("nav-create"));
}

function cancelEdit() {
  state.editingId = null;
  setEditMode(false);
  resetForm(false);
}

async function deletePlaybook(id) {
  const sure = confirm("Delete this playbook? For library playbooks, this reverts your override.");
  if (!sure) return;

  const res = await fetch(`${API_DELETE}?id=${encodeURIComponent(id)}`, { method: "DELETE" });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || body.error) {
    alert(body.error || "Delete failed.");
    return;
  }
  await refreshData();
  showPanel("home", document.getElementById("nav-home"));
}

function resetForm(rebuild = true) {
  ["f-name", "f-scenario", "f-detection", "f-primary-query"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });
  const cat = document.getElementById("f-cat");
  const sev = document.getElementById("f-sev");
  if (cat) cat.value = "";
  if (sev) sev.value = "high";

  state.mitreTags = [];
  renderMitreTags();
  if (rebuild) resetBuilder();
}

function validateSigma(ruleText) {
  if (!ruleText || !String(ruleText).trim()) return null;
  if (!window.jsyaml) return { ok: false, reason: "YAML parser unavailable" };
  try {
    const parsed = window.jsyaml.load(ruleText);
    const required = ["title", "status", "logsource", "detection"];
    const missing = required.filter((k) => !parsed?.[k]);
    if (missing.length) return { ok: false, reason: `Missing: ${missing.join(", ")}` };
    if (!parsed.detection?.condition) return { ok: false, reason: "Missing: detection.condition" };
    return { ok: true, reason: "OK" };
  } catch (err) {
    return { ok: false, reason: "Invalid YAML" };
  }
}

function printPlaybook() {
  window.print();
}

function exportSoar(pbId) {
  const pb = getPlaybookById(pbId);
  if (!pb) return;
  const payload = {
    format: "soc-playbook-soar-v1",
    exportedAt: new Date().toISOString(),
    id: pb.id, name: pb.name, type: pb.type,
    severity: pb.severity || pb.sev, category: pb.cat,
    mitre: pb.mitre, scenario: pb.scenario,
    investigation: pb.investigation
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `soar-${pb.id}-${(pb.name || '').replace(/[^a-z0-9]/gi,'_').toLowerCase()}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

async function refreshData() {
  await loadCustomPlaybooks();
  buildMergedPlaybooks();
  renderSidebar();
  renderCards();
  updateCardCount();
  renderNavigatorPanel();
}

function updatePrimaryQueryLabel() {
  const tool = state.activeTools[0] || "splunk";
  const toolLabel = ALL_TOOLS[tool]?.label || tool;
  const lbl = document.getElementById("f-primary-query-label");
  const ta  = document.getElementById("f-primary-query");
  if (lbl) lbl.innerHTML = `Primary ${toolLabel} query <span style="font-weight:400;color:var(--text3)">(optional)</span>`;
  if (ta)  ta.placeholder = `Enter an initial triage query for ${toolLabel}…`;
}

async function loadToolConfig() {
  try {
    const r = await fetch("cgi-bin/get_config.sh");
    if (!r.ok) return;
    const cfg = await r.json();
    if (Array.isArray(cfg.tools) && cfg.tools.length > 0) {
      const valid = cfg.tools.filter(t => ALL_TOOLS[t]).slice(0, 6);
      if (valid.length > 0) state.activeTools = valid;
    }
  } catch (_) { /* network error or CGI unavailable — use defaults */ }
  DEFAULT_TOOL = state.activeTools.includes(DEFAULT_TOOL_FALLBACK)
    ? DEFAULT_TOOL_FALLBACK
    : state.activeTools[0];
  updatePrimaryQueryLabel();
}

async function init() {
  try {
    await loadToolConfig();
    await loadMitreTechniques();
    await loadManifest();
    await loadLibraryDetails();
    await refreshData();

    const cardSearch = document.getElementById("card-search");
    if (cardSearch) {
      cardSearch.addEventListener("input", (e) => {
        state.activeCardSearch = e.target.value || "";
        renderCards();
      });
    }

    populateMitreDatalist();
    const mitreInput = document.querySelector(".mitre-tag-input");
    if (mitreInput) {
      mitreInput.addEventListener("input", (e) => updateMitreInputHint(e.target.value || ""));
    }
    updateMitreInputHint("");

    setEditMode(false);
    resetBuilder();
    showPanel("home", document.getElementById("nav-home"));

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeMobileNav();
    });

    window.addEventListener("resize", () => {
      if (!isMobileViewport()) closeMobileNav();
    });
  } catch (err) {
    console.error(err);
    alert("Failed to initialize playbooks. Check manifest/data files and CGI endpoints.");
  }
}

window.toggleGroup = toggleGroup;
window.showPanel = showPanel;
window.searchNav = searchNav;
window.filterCards = filterCards;
window.openPlaybook = openPlaybook;
window.switchToolTab = switchToolTab;
window.addStep = addStep;
window.addMitreTag = addMitreTag;
window.removeMitre = removeMitre;
window.savePlaybook = savePlaybook;
window.resetForm = resetForm;
window.startEdit = startEdit;
window.cancelEdit = cancelEdit;
window.deletePlaybook = deletePlaybook;
window.renumberAllSteps = renumberAllSteps;
window.toggleMobileNav = toggleMobileNav;
window.closeMobileNav = closeMobileNav;
window.updateMitreInputHint = updateMitreInputHint;
window.updateNavigatorLayer = updateNavigatorLayer;
window.downloadNavigatorLayer = downloadNavigatorLayer;
window.openNavigatorInNewTab = openNavigatorInNewTab;
window.filterSeverity = filterSeverity;
window.filterSource = filterSource;
window.filterSourceSelect = filterSourceSelect;
window.filterSeveritySelect = filterSeveritySelect;
window.toggleChecklist = toggleChecklist;
window.toggleChecklistStep = toggleChecklistStep;
window.resetChecklist = resetChecklist;
window.printPlaybook = printPlaybook;
window.exportSoar = exportSoar;
window.toggleTheme = toggleTheme;
window.openWizard = openWizard;
window.closeWizard = closeWizard;
window.wizardNext = wizardNext;
window.wizardPrev = wizardPrev;
window.wizardSave = wizardSave;
window.addWizardMitreTag = addWizardMitreTag;
window.removeWizardMitreTag = removeWizardMitreTag;
window.addWizardStep = addWizardStep;

// ── WIZARD ──────────────────────────────────────────────────────────────────
const WIZARD_STEPS = [
  { id: "basic",     title: "Basic Info"      },
  { id: "context",   title: "Context"         },
  { id: "detection", title: "Detection"       },
  { id: "det",       title: "Analysis Steps"  },
  { id: "cont",      title: "Containment"     },
  { id: "erad",      title: "Eradication"     },
  { id: "rec",       title: "Recovery"        },
  { id: "review",    title: "Review & Save"   },
];

const wizardData = {
  name: "", scenario: "", cat: "", sev: "high",
  detection: "", mitreTags: [], primaryQuery: "",
  detSteps: [], contSteps: [], eradSteps: [], recSteps: [],
};

let wizardStep = 0;

function openWizard() {
  Object.assign(wizardData, {
    name: "", scenario: "", cat: "", sev: "high",
    detection: "", mitreTags: [], primaryQuery: "",
    detSteps: [], contSteps: [], eradSteps: [], recSteps: [],
  });
  wizardStep = 0;
  const overlay = document.getElementById("wizard-overlay");
  if (overlay) overlay.style.display = "flex";
  renderWizardStep();
}

function closeWizard() {
  const overlay = document.getElementById("wizard-overlay");
  if (overlay) overlay.style.display = "none";
}

function renderWizardProgress() {
  const prog = document.getElementById("wiz-progress");
  if (!prog) return;
  prog.innerHTML = WIZARD_STEPS.map((s, i) => {
    const cls = i < wizardStep ? "done" : i === wizardStep ? "active" : "";
    return `<div class="wiz-step-dot ${cls}" title="${esc(s.title)}">
      <span class="wiz-dot-num">${i < wizardStep ? "✓" : i + 1}</span>
      <span class="wiz-dot-label">${esc(s.title)}</span>
    </div>`;
  }).join("");
}

function renderWizardStep() {
  renderWizardProgress();
  const numEl = document.getElementById("wiz-step-num");
  if (numEl) numEl.textContent = wizardStep + 1;
  const labelEl = document.getElementById("wiz-step-label");
  if (labelEl) labelEl.textContent = WIZARD_STEPS[wizardStep].title;

  const body = document.getElementById("wiz-body");
  if (body) {
    body.innerHTML = wizardStepContent();
    body.scrollTop = 0;
  }

  const prev = document.getElementById("wiz-prev");
  const next = document.getElementById("wiz-next");
  if (prev) prev.style.visibility = wizardStep === 0 ? "hidden" : "visible";
  if (next) {
    const isLast = wizardStep === WIZARD_STEPS.length - 1;
    next.style.display = isLast ? "none" : "";
    next.textContent = wizardStep === WIZARD_STEPS.length - 2 ? "Review →" : "Next →";
  }

  // Populate step builders after DOM is ready
  if (wizardStep === 3) populateWizardStepBuilder("wiz-det-steps",  wizardData.detSteps);
  if (wizardStep === 4) populateWizardStepBuilder("wiz-cont-steps", wizardData.contSteps);
  if (wizardStep === 5) populateWizardStepBuilder("wiz-erad-steps", wizardData.eradSteps);
  if (wizardStep === 6) populateWizardStepBuilder("wiz-rec-steps",  wizardData.recSteps);

  // Re-render MITRE tags on context step
  if (wizardStep === 1) setTimeout(() => renderWizardMitreTags(), 0);

  // Update primary query label
  if (wizardStep === 2) {
    const first = state.activeTools[0];
    const lbl = first ? (ALL_TOOLS[first]?.label || first) : "Primary";
    const el = document.getElementById("wiz-primary-query-label");
    if (el) el.innerHTML = `${esc(lbl)} query <span style="font-weight:400;color:var(--text3)">(optional)</span>`;
  }
}

function wizardStepContent() {
  const d = wizardData;
  const cats = ["Malware","Insider Threat","Cloud","Identity","Application","Network","Supply Chain","Data","Other"];
  const sevs = [["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"]];

  switch (wizardStep) {
    case 0:
      return `
        <div class="wiz-step-intro">Enter the basic identifying details for your new playbook.</div>
        <div class="form-grid">
          <div class="form-group form-full">
            <label class="form-label">Playbook title <span>*</span></label>
            <input class="form-input" id="wiz-name" value="${esc(d.name)}" placeholder="e.g. Suspicious PowerShell Execution" maxlength="80">
          </div>
          <div class="form-group">
            <label class="form-label">Category <span>*</span></label>
            <select class="form-select" id="wiz-cat">
              <option value="">Select category...</option>
              ${cats.map(c => `<option value="${c}"${d.cat===c?" selected":""}>${c}</option>`).join("")}
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Severity</label>
            <select class="form-select" id="wiz-sev">
              ${sevs.map(([v,l]) => `<option value="${v}"${d.sev===v?" selected":""}>${l}</option>`).join("")}
            </select>
          </div>
        </div>`;

    case 1:
      return `
        <div class="wiz-step-intro">Describe what this playbook covers and map it to MITRE ATT&amp;CK techniques.</div>
        <div class="form-grid">
          <div class="form-group form-full">
            <label class="form-label">Scenario description <span>*</span></label>
            <textarea class="form-textarea" id="wiz-scenario" rows="5" placeholder="Describe the alert scenario and what has been detected...">${esc(d.scenario)}</textarea>
          </div>
          <div class="form-group form-full">
            <label class="form-label">MITRE ATT&amp;CK technique IDs</label>
            <div class="mitre-input-row">
              <input class="mitre-tag-input" id="wiz-mitre-input" list="mitre-id-suggestions" placeholder="T1059.001" maxlength="20" oninput="updateMitreInputHint(this.value)">
              <button class="btn btn-secondary" style="padding:4px 10px;font-size:11px" onclick="addWizardMitreTag()">+ Add</button>
            </div>
            <div id="wiz-mitre-help" class="mitre-input-help">Enter ATT&amp;CK ID (e.g. T1059.001). Click a tag to open the ATT&amp;CK page.</div>
            <div id="wiz-mitre-display" style="display:flex;gap:4px;flex-wrap:wrap;margin-top:6px"></div>
          </div>
        </div>`;

    case 2:
      return `
        <div class="wiz-step-intro">Specify detection data sources and provide an initial triage query.</div>
        <div class="form-grid">
          <div class="form-group form-full">
            <label class="form-label">Detection sources</label>
            <input class="form-input" id="wiz-detection" value="${esc(d.detection)}" placeholder="e.g. Windows Security logs, firewall, DNS, EDR alerts">
          </div>
          <div class="form-group form-full">
            <label class="form-label" id="wiz-primary-query-label">Primary investigation query <span style="font-weight:400;color:var(--text3)">(optional)</span></label>
            <textarea class="form-textarea" id="wiz-primary-query" rows="5" style="font-family:var(--mono);font-size:12px" placeholder="Enter an initial triage query...">${esc(d.primaryQuery)}</textarea>
          </div>
        </div>`;

    case 3:
    case 4:
    case 5:
    case 6: {
      const phaseLabels = ["Detection &amp; Analysis", "Containment", "Eradication", "Recovery &amp; Lessons Learned"];
      const phaseDescs  = [
        "Add investigation and analysis steps for this incident type.",
        "Add steps to contain the threat and limit further damage.",
        "Add steps to remove the threat and harden the environment.",
        "Add steps to restore systems and capture lessons learned.",
      ];
      const containerIds = ["wiz-det-steps","wiz-cont-steps","wiz-erad-steps","wiz-rec-steps"];
      const idx = wizardStep - 3;
      return `
        <div class="wiz-step-intro">${phaseDescs[idx]}</div>
        <div class="step-builder">
          <div class="step-builder-head">${phaseLabels[idx]}
            <button class="btn btn-secondary" style="padding:3px 9px;font-size:11px" onclick="addWizardStep('${containerIds[idx]}')">+ Step</button>
          </div>
          <div class="step-builder-body" id="${containerIds[idx]}"></div>
          <div class="add-step-btn" onclick="addWizardStep('${containerIds[idx]}')">+ Add step</div>
        </div>`;
    }

    case 7: {
      const stepCounts = [
        ["Analysis", d.detSteps.length],
        ["Containment", d.contSteps.length],
        ["Eradication", d.eradSteps.length],
        ["Recovery", d.recSteps.length],
      ];
      return `
        <div class="wiz-step-intro">Review your playbook. Click <strong>Save Playbook</strong> to publish it to the library.</div>
        <div class="wiz-review">
          <div class="wiz-review-row"><span class="wiz-review-label">Title</span><span>${esc(d.name || "(not set)")}</span></div>
          <div class="wiz-review-row"><span class="wiz-review-label">Category</span><span>${esc(d.cat || "(not set)")}</span></div>
          <div class="wiz-review-row"><span class="wiz-review-label">Severity</span><span>${esc(d.sev)}</span></div>
          <div class="wiz-review-row"><span class="wiz-review-label">Scenario</span><span style="white-space:pre-wrap">${esc(d.scenario ? d.scenario.substring(0,200)+(d.scenario.length>200?"…":"") : "(not set)")}</span></div>
          <div class="wiz-review-row"><span class="wiz-review-label">MITRE Tags</span><span>${d.mitreTags.length ? d.mitreTags.map(t=>`<span class="badge b-teal">${esc(t)}</span>`).join(" ") : "(none)"}</span></div>
          <div class="wiz-review-row"><span class="wiz-review-label">Detection Sources</span><span>${esc(d.detection || "(not set)")}</span></div>
          <div class="wiz-review-row"><span class="wiz-review-label">Primary Query</span><span>${d.primaryQuery ? '<span class="badge b-blue">✓ provided</span>' : "(not set)"}</span></div>
          ${stepCounts.map(([lbl,cnt]) => `<div class="wiz-review-row"><span class="wiz-review-label">${lbl} Steps</span><span>${cnt} step${cnt!==1?"s":""}</span></div>`).join("")}
        </div>
        <div class="wiz-review-save">
          <button class="btn btn-primary" style="font-size:14px;padding:8px 22px" onclick="wizardSave()">💾 Save Playbook</button>
          <button class="btn btn-secondary" onclick="wizardStep=0;renderWizardStep()">← Edit from Start</button>
        </div>`;
    }

    default: return "";
  }
}

function renderWizardMitreTags() {
  const host = document.getElementById("wiz-mitre-display");
  if (!host) return;
  host.innerHTML = wizardData.mitreTags.map(tag => {
    const info = getMitreTechniqueInfo(tag);
    const name = info?.name ? `<span class="mitre-chip-name">${esc(info.name)}</span>` : "";
    return `<span class="mitre-chip">${renderMitreLink(tag, false)}${name}<button class="mitre-chip-remove" onclick="removeWizardMitreTag('${esc(tag)}')" aria-label="Remove ${esc(tag)}">×</button></span>`;
  }).join("");
}

function addWizardMitreTag() {
  const input = document.getElementById("wiz-mitre-input");
  if (!input) return;
  const value = normalizeMitreId(input.value);
  if (!value) return;
  if (!wizardData.mitreTags.includes(value)) wizardData.mitreTags.push(value);
  input.value = "";
  renderWizardMitreTags();
}

function removeWizardMitreTag(tag) {
  wizardData.mitreTags = wizardData.mitreTags.filter(t => t !== tag);
  renderWizardMitreTags();
}

function addWizardStep(containerId) {
  const body = document.getElementById(containerId);
  if (!body) return;
  const index = body.querySelectorAll(".step-row").length;
  body.insertAdjacentHTML("beforeend", stepRowTemplate(index, {}));
}

function populateWizardStepBuilder(containerId, steps) {
  const body = document.getElementById(containerId);
  if (!body) return;
  body.innerHTML = "";
  if (!steps.length) {
    addWizardStep(containerId);
  } else {
    steps.forEach((s, i) => body.insertAdjacentHTML("beforeend", stepRowTemplate(i, s)));
  }
}

function wizardSaveCurrentStep() {
  switch (wizardStep) {
    case 0:
      wizardData.name = document.getElementById("wiz-name")?.value.trim() || "";
      wizardData.cat  = document.getElementById("wiz-cat")?.value || "";
      wizardData.sev  = document.getElementById("wiz-sev")?.value || "high";
      break;
    case 1:
      wizardData.scenario = document.getElementById("wiz-scenario")?.value.trim() || "";
      break;
    case 2:
      wizardData.detection    = document.getElementById("wiz-detection")?.value.trim() || "";
      wizardData.primaryQuery = document.getElementById("wiz-primary-query")?.value.trim() || "";
      break;
    case 3: wizardData.detSteps  = readStepRows("wiz-det-steps");  break;
    case 4: wizardData.contSteps = readStepRows("wiz-cont-steps"); break;
    case 5: wizardData.eradSteps = readStepRows("wiz-erad-steps"); break;
    case 6: wizardData.recSteps  = readStepRows("wiz-rec-steps");  break;
  }
}

function wizardValidateStep() {
  switch (wizardStep) {
    case 0:
      if (!document.getElementById("wiz-name")?.value.trim()) {
        alert("Please enter a playbook title.");
        return false;
      }
      if (!document.getElementById("wiz-cat")?.value) {
        alert("Please select a category.");
        return false;
      }
      break;
    case 1:
      if (!document.getElementById("wiz-scenario")?.value.trim()) {
        alert("Please enter a scenario description.");
        return false;
      }
      break;
  }
  return true;
}

function wizardNext() {
  if (!wizardValidateStep()) return;
  wizardSaveCurrentStep();
  wizardStep = Math.min(wizardStep + 1, WIZARD_STEPS.length - 1);
  renderWizardStep();
}

function wizardPrev() {
  wizardSaveCurrentStep();
  wizardStep = Math.max(wizardStep - 1, 0);
  renderWizardStep();
}

async function wizardSave() {
  const { name, scenario, cat, sev, detection, mitreTags, primaryQuery,
          detSteps, contSteps, eradSteps, recSteps } = wizardData;

  if (!name || !scenario || !cat) {
    alert("Please complete the title, scenario, and category (steps 1 & 2).");
    return;
  }

  const payload = {
    name, scenario, cat, sev, type: cat, source: "custom",
    detection, mitre: [...mitreTags], primaryQuery,
    investigation: {
      detectionAnalysis: detSteps,
      containment: contSteps,
      eradication: eradSteps,
      recovery: recSteps,
    }
  };

  try {
    const res = await fetch(API_SAVE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (!res.ok || body.error) throw new Error(body.error || "Failed to save playbook");
    closeWizard();
    await refreshData();
    showPanel("home", document.getElementById("nav-home"));
  } catch (err) {
    alert(err.message || "Unable to save playbook.");
  }
}

function initTheme() {
  const stored = localStorage.getItem('pb-theme') || 'dark';
  applyTheme(stored, false);
}

function applyTheme(theme, save = true) {
  document.documentElement.setAttribute('data-theme', theme);
  if (save) localStorage.setItem('pb-theme', theme);
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = theme === 'dark' ? '☀' : '🌙';
  const lightLink = document.getElementById('hljs-light');
  const darkLink  = document.getElementById('hljs-dark');
  if (lightLink) lightLink.disabled = (theme === 'dark');
  if (darkLink)  darkLink.disabled  = (theme === 'light');
  if (window.hljs) {
    document.querySelectorAll('pre code').forEach(b => hljs.highlightElement(b));
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}

document.addEventListener("DOMContentLoaded", () => { initTheme(); init(); });
