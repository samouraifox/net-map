# net-map · Roadmap

The current spec — [2026-05-25-netmap-design.md](superpowers/specs/2026-05-25-netmap-design.md) — describes **v1**: a continuous LAN inventory tool with a topology visualizer. It is intentionally focused on _discovery + visualization_, not analysis.

The longer-term direction for net-map is to grow it into a **cybersecurity analyst tool/product**, layered on top of the v1 inventory engine.

---

## Beyond v1 — direction

### v2 — Vulnerability awareness
- **Service-version → CVE correlation.** For each detected `(service, version)` pair, look up known CVEs (NVD JSON feeds for offline use, or per-query lookup via the NVD API / OSV.dev).
- **Per-host vulnerability rollup** in the side panel: list applicable CVEs, severities, publication dates, vector strings.
- **Host risk dot** driven by worst-case CVE severity (CVSS) rather than just static port category.

### v3 — Exploit scoring
- **EPSS** (Exploit Prediction Scoring System) per CVE — probability of exploitation in the wild.
- **CISA KEV** (Known Exploited Vulnerabilities) catalog membership — authoritative "currently exploited" flag.
- **Exploit availability** signal: Metasploit module presence, public PoC (e.g. ExploitDB).
- **Composite host risk score** combining CVE severity × EPSS × KEV × exposure (public reachability, sensitive ports open, host trust status, lateral-movement potential).

### v4+ — Analyst workflow
- Saved investigations / "case" objects — pin hosts, attach evidence, write findings, generate report.
- Scheduled posture reports (network-level risk trend over time).
- Multi-tenant / multi-network views for analysts covering several environments.
- Possible product packaging if it grows useful enough to share publicly.

---

## Implications for v1 implementation

These items are **not** in v1 scope. But while implementing v1, preserve clean extension points so v2+ work is additive, not a rewrite:

- **Schema.** The v1 `port` table already carries `service` + `version` — the natural join keys for future CVE lookup. Keep them populated reliably.
- **Events.** The `event.kind` column is a free-text string; future event kinds (`cve.found`, `exploit.kev`, `risk.changed`) slot in without schema changes.
- **UI side panel.** The accordion layout is section-extensible by design — additional "Vulnerabilities" / "Risk" sections drop in without restructuring the panel.
- **Risk coloring.** Don't bake the v1 static port-category rules so deep that swapping in CVE-driven coloring later is painful. Keep the risk-classification function isolated and replaceable.
- **OUI / external data.** The same "bundled data + `update-*` CLI command" pattern used for OUI in v1 will be reused for NVD/EPSS/KEV feeds in v2.

Nothing on this page is committed work — it is the stated direction so v1 choices don't accidentally close doors.
