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

// -------------------- placeholders for sections 2-4 --------------------
// These will be replaced by the real implementations in Tasks 24-26.
function initGraph() {}
function renderGraph() {}
function connectSse() {}
function appendEvent(_ev) {}
