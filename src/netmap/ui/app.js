// net-map UI — section 1: state, API client, helpers, bootstrap.
// Sections 2-4 (cytoscape, SSE, host-detail/timeline) are appended below.

"use strict";

const State = {
  hosts: new Map(),          // id -> HostSummary
  hostDetail: null,          // HostDetail | null
  subnets: [],
  events: [],                // ring buffer, newest first, capped at 200
  selectedHostId: null,
  selectedSubnetId: null,
  scanning: false,
  cy: null,                  // cytoscape instance
  sse: null,                 // EventSource | null
  lastEventTs: null,         // ISO string for catch-up on reconnect
  sseBackoffMs: 1000,
};

const TIMELINE_CAP = 200;

// -------------------- helpers --------------------

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "dataset") for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = dv;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v === false || v == null) continue;
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children) {
    if (c == null || c === false) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function fmtRelative(iso) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  const ageS = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (ageS < 60) return ageS + "s ago";
  if (ageS < 3600) return Math.floor(ageS / 60) + "m ago";
  return Math.floor(ageS / 3600) + "h ago";
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false });
}

// Device-icon resolver: returns one of the <symbol id="..."> names defined in index.html.
function iconForDevice(deviceType) {
  if (deviceType === "router") return "ic-router";
  if (deviceType === "server") return "ic-server";
  if (deviceType === "endpoint") return "ic-laptop";
  if (deviceType === "iot") return "ic-iot";
  return "ic-unknown";
}

// Port-risk classifier (pure). High → SMB / RDP / Telnet / unauth DB.
// Elev → SSH, admin web UIs (9000–9999). Normal → HTTP family. Info → everything else.
const RISK_HIGH_TCP = new Set([23, 135, 139, 445, 1433, 3306, 3389, 5432, 27017]);
const RISK_NORM_TCP = new Set([80, 443, 8080, 8443]);

function portRisk(proto, port) {
  if (proto === "tcp") {
    if (RISK_HIGH_TCP.has(port)) return { tier: "high", label: "high" };
    if (port === 22)             return { tier: "elev", label: "elev" };
    if (port >= 9000 && port < 10000) return { tier: "elev", label: "elev" };
    if (RISK_NORM_TCP.has(port)) return { tier: "norm", label: "normal" };
  }
  return { tier: "info", label: "info" };
}

// -------------------- API client --------------------

async function fetchJson(path, opts = {}) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`;
    try { detail = (await r.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return r.json();
}

const api = {
  hosts: ({ subnet, q } = {}) => {
    const p = new URLSearchParams();
    if (subnet != null) p.set("subnet", subnet);
    if (q) p.set("q", q);
    const qs = p.toString();
    return fetchJson("/api/v1/hosts" + (qs ? "?" + qs : ""));
  },
  hostDetail: (id) => fetchJson("/api/v1/hosts/" + id),
  subnets: () => fetchJson("/api/v1/subnets"),
  scans: () => fetchJson("/api/v1/scans?limit=50"),
  events: ({ since, limit = 200 } = {}) => {
    const p = new URLSearchParams();
    if (since) p.set("since", since);
    p.set("limit", String(limit));
    return fetchJson("/api/v1/events?" + p.toString());
  },
  postScan: (body) => fetchJson("/api/v1/scans", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  }),
};

// -------------------- toast --------------------

function toast(message, { kind = "error", ms = 5000 } = {}) {
  const stack = $("#toastStack");
  if (!stack) return;
  const t = el("div", { class: "toast " + kind, role: "status" }, message);
  stack.appendChild(t);
  setTimeout(() => t.remove(), ms);
}

// -------------------- topbar / sidebar render --------------------

function renderTopbar() {
  const crumb = $("#crumb");
  const kpis = $("#kpis");
  const live = $("#liveIndicator");
  const btn = $("#scanNowBtn");

  const hostCount = State.hosts.size;
  let openPorts = 0;
  let risk = 0;
  for (const h of State.hosts.values()) {
    openPorts += h.open_port_count || 0;
  }
  if (State.hostDetail) {
    for (const p of State.hostDetail.open_ports || []) {
      const r = portRisk(p.protocol, p.number);
      if (r.tier === "high") risk += 1;
    }
  }

  const sub = State.subnets.find((s) => s.id === State.selectedSubnetId);
  const subnetLabel = sub ? sub.cidr : (State.subnets[0]?.cidr || "—");
  const mode = State.scanning ? "scanning" : "discover";
  crumb.textContent = `~/networks # ${mode} · ${hostCount} hosts · ${subnetLabel}`;

  kpis.replaceChildren(
    el("div", { class: "kpi" }, "hosts ", el("span", { class: "v" }, String(hostCount))),
    el("div", { class: "kpi" }, "ports ", el("span", { class: "v" }, String(openPorts))),
    el("div", { class: "kpi risk" }, "risk ", el("span", { class: "v" }, String(risk))),
  );

  btn.disabled = State.scanning;
  btn.textContent = State.scanning ? "scanning…" : "scan now";
  live.dataset.state = State.sse && State.sse.readyState === 1 ? "live" : "reconnecting";
  live.textContent = live.dataset.state === "live" ? "live" : "reconnecting…";
}

function renderSidebar() {
  const list = $("#subnetList");
  list.replaceChildren();
  for (const s of State.subnets) {
    list.appendChild(el(
      "li",
      {
        "aria-current": s.id === State.selectedSubnetId ? "true" : "false",
        onclick: () => {
          State.selectedSubnetId =
            State.selectedSubnetId === s.id ? null : s.id;
          renderSidebar(); renderGraph();
        },
      },
      el("div", { class: "cidr" }, s.cidr),
      el("div", { class: "meta" },
        `${s.source} · hop ${s.hop_distance}${s.enabled ? "" : " · disabled"}`),
    ));
  }
}

// -------------------- bootstrap --------------------

async function bootstrap() {
  try {
    const [hosts, subnets] = await Promise.all([api.hosts(), api.subnets()]);
    State.subnets = subnets;
    State.hosts.clear();
    for (const h of hosts) State.hosts.set(h.id, h);

    const initialEvents = await api.events({ limit: 50 });
    for (const ev of initialEvents.reverse()) appendEvent(ev);

    initGraph();         // section 2
    renderSidebar();
    renderTopbar();
    renderGraph();       // section 2

    connectSse();        // section 3

    $("#scanNowBtn").addEventListener("click", onScanNow);
  } catch (exc) {
    toast("bootstrap failed: " + exc.message);
    console.error(exc);
  }
}

async function onScanNow() {
  try {
    await api.postScan({ mode: "default" });
  } catch (exc) {
    toast("scan request rejected: " + exc.message);
  }
}

window.addEventListener("DOMContentLoaded", bootstrap);

// -------------------- section 2: Cytoscape graph --------------------

function _registerCoseBilkent() {
  if (window.cytoscape && window.cytoscapeCoseBilkent) {
    cytoscape.use(window.cytoscapeCoseBilkent);
  }
}

// Inline an <svg><use href="#ic-router"/></svg> as a data URI suitable for
// Cytoscape's `background-image`. Cytoscape clones the document node so we
// can't directly reference `<use href>` — we serialize the resolved symbol.
const ICON_SVG_CACHE = new Map();
function iconDataUri(name, color) {
  const key = `${name}|${color}`;
  if (ICON_SVG_CACHE.has(key)) return ICON_SVG_CACHE.get(key);
  const symbol = document.getElementById(name);
  if (!symbol) return "";
  const viewBox = symbol.getAttribute("viewBox") || "0 0 24 24";
  const inner = symbol.innerHTML;
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' viewBox='${viewBox}' ` +
    `fill='none' stroke='${color}' stroke-width='1.6' ` +
    `stroke-linecap='round' stroke-linejoin='round'>${inner}</svg>`;
  const uri = "data:image/svg+xml;utf8," + encodeURIComponent(svg);
  ICON_SVG_CACHE.set(key, uri);
  return uri;
}

function hostNodeColor(h) {
  // Risk dominates color. Default = text. Trusted hosts get the accent.
  // Heuristic: any open port -> normal; trusted overrides; otherwise muted.
  if (h.trusted) return getCss("--accent");
  if ((h.open_port_count || 0) > 0) return getCss("--text");
  return getCss("--text-muted");
}

function getCss(varname) {
  return getComputedStyle(document.documentElement).getPropertyValue(varname).trim();
}

function initGraph() {
  _registerCoseBilkent();
  State.cy = cytoscape({
    container: document.getElementById("cy"),
    wheelSensitivity: 0.15,
    minZoom: 0.3, maxZoom: 3.0,
    style: [
      {
        selector: "node[type='subnet']",
        style: {
          "background-color": "transparent",
          "border-color": getCss("--border"),
          "border-style": "dashed",
          "border-width": 1,
          "shape": "round-rectangle",
          "label": "data(label)",
          "text-valign": "top",
          "text-halign": "left",
          "text-margin-x": 6,
          "text-margin-y": 4,
          "color": getCss("--text-muted"),
          "font-size": 10,
          "font-family": "Geist Mono, monospace",
          "padding": 16,
        },
      },
      {
        selector: "node[type='host']",
        style: {
          "shape": "round-rectangle",
          "width": 36, "height": 36,
          "background-color": getCss("--surface"),
          "background-image": "data(iconUri)",
          "background-fit": "contain",
          "background-clip": "none",
          "border-color": getCss("--border"),
          "border-width": 1,
          "label": "data(label)",
          "text-valign": "bottom",
          "text-margin-y": 6,
          "color": getCss("--text"),
          "font-size": 10,
          "font-family": "Geist Mono, monospace",
        },
      },
      {
        selector: "node[type='host'][risk='high']",
        style: { "border-color": getCss("--risk-red"), "border-width": 2 },
      },
      {
        selector: "node[type='host'][risk='elev']",
        style: { "border-color": getCss("--risk-yel") },
      },
      {
        selector: "node:selected",
        style: {
          "border-color": getCss("--accent"),
          "border-width": 2,
        },
      },
      {
        selector: "edge",
        style: {
          "width": 1,
          "line-color": getCss("--border"),
          "curve-style": "bezier",
        },
      },
      {
        selector: "edge[kind='gateway']",
        style: { "width": 2, "line-color": getCss("--accent") },
      },
    ],
  });

  State.cy.on("tap", "node[type='host']", (evt) => {
    const id = Number(evt.target.id().replace(/^h/, ""));
    selectHost(id);
  });
  State.cy.on("tap", (evt) => {
    if (evt.target === State.cy) selectHost(null);
  });
}

function _maxRiskFor(host) {
  // We only know open ports from host detail; in the summary view we
  // approximate via open_port_count (any open ports → "norm"). Real risk
  // colors come once the user opens the host detail.
  return (host.open_port_count || 0) > 0 ? "norm" : "info";
}

function renderGraph() {
  if (!State.cy) return;
  const cy = State.cy;
  cy.batch(() => {
    cy.elements().remove();

    const subnetById = new Map(State.subnets.map((s) => [s.id, s]));
    const subnetByCidr = new Map(State.subnets.map((s) => [s.cidr, s]));
    for (const s of State.subnets) {
      cy.add({
        group: "nodes",
        data: { id: "s" + s.id, type: "subnet", label: s.cidr },
      });
    }

    for (const h of State.hosts.values()) {
      const parent = _subnetForIp(h.primary_ip, State.subnets);
      cy.add({
        group: "nodes",
        data: {
          id: "h" + h.id, type: "host",
          parent: parent ? "s" + parent.id : undefined,
          label: h.hostname || h.primary_ip,
          iconUri: iconDataUri(iconForDevice(h.device_type), hostNodeColor(h)),
          risk: _maxRiskFor(h),
        },
      });
    }

    cy.layout({
      name: "cose-bilkent",
      animate: false,
      nodeRepulsion: 4500,
      idealEdgeLength: 80,
      tile: true,
      padding: 30,
    }).run();
  });

  $("#canvasEmpty").hidden = State.hosts.size > 0;
}

function _subnetForIp(ip, subnets) {
  // Lightweight CIDR membership check (IPv4). Returns first matching subnet.
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n))) return null;
  const ipInt = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  for (const s of subnets) {
    const [base, maskStr] = s.cidr.split("/");
    const baseParts = base.split(".").map(Number);
    if (baseParts.length !== 4 || baseParts.some((n) => isNaN(n))) continue;
    const baseInt = ((baseParts[0] << 24) | (baseParts[1] << 16) |
                     (baseParts[2] << 8) | baseParts[3]) >>> 0;
    const mask = (~((1 << (32 - Number(maskStr))) - 1)) >>> 0;
    if ((ipInt & mask) === (baseInt & mask)) return s;
  }
  return null;
}

function selectHost(id) {
  State.selectedHostId = id;
  if (State.cy) {
    State.cy.elements(":selected").unselect();
    if (id != null) {
      const node = State.cy.getElementById("h" + id);
      if (node && node.length) node.select();
    }
  }
  if (id == null) {
    State.hostDetail = null;
    renderHostDetail();
    return;
  }
  api.hostDetail(id).then((d) => {
    State.hostDetail = d;
    renderHostDetail();
    renderTopbar();
  }).catch((exc) => toast("could not load host: " + exc.message));
}

// -------------------- section 3: SSE + reducer (Task 25) --------------------
function connectSse() {}

// -------------------- section 4: host detail + timeline (Task 26) --------------------
function renderHostDetail() {}
function appendEvent(_ev) {}
