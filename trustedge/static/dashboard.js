"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  token: "",
  data: null,
  view: "overview",
  selected: null,
  paused: false,
  fetching: false,
  history: [],
  historyIp: null,
  connected: false,
  stale: false,
};
const colors = {
  TRUSTED: "#22c55e",
  CAUTIOUS: "#f59e0b",
  QUARANTINE: "#ef4444",
  PENDING: "#8892a4",
};
const titles = {
  overview: [
    "Gateway overview",
    "A clear view of every device, decision, and boundary.",
  ],
  devices: [
    "Device registry",
    "Know what is connected. Control what it can reach.",
  ],
  traffic: [
    "Traffic & detections",
    "Real window metadata and the signals behind each decision.",
  ],
  trust: [
    "Trust intelligence",
    "Understand how local behavior becomes an enforcement decision.",
  ],
  topology: [
    "Network topology",
    "A logical map of the gateway boundary and enrolled devices.",
  ],
  audit: [
    "Audit trail",
    "A local record of lifecycle changes, detections, and policy outcomes.",
  ],
  system: [
    "Gateway health",
    "Capture, persistence, and system resources—observed locally.",
  ],
};
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = String(text);
  return n;
}
function replace(id, ...nodes) {
  $(id).replaceChildren(...nodes);
}
function num(value, digits = 0) {
  return Number.isFinite(value)
    ? value.toLocaleString(undefined, { maximumFractionDigits: digits })
    : "—";
}
function bytes(v) {
  if (!Number.isFinite(v)) return "Unavailable";
  if (v < 1024) return `${num(v)} B`;
  const i = Math.min(3, Math.floor(Math.log(v) / Math.log(1024)));
  return `${num(v / 1024 ** i, 1)} ${["B", "KiB", "MiB", "GiB"][i]}`;
}
function stamp(value) {
  if (!value) return "—";
  const normalized = /^\d{4}-\d\d-\d\d \d\d:/.test(value)
    ? value.replace(" ", "T") + "Z"
    : value;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime())
    ? "—"
    : date.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}
function badge(tier) {
  return el(
    "span",
    `badge ${tier === "TRUSTED" ? "green" : tier === "CAUTIOUS" ? "amber" : tier === "QUARANTINE" ? "red" : "neutral"}`,
    tier || "UNCONFIRMED",
  );
}
function empty(title, description = "") {
  const n = el("div", "empty");
  n.append(el("strong", "", title), el("span", "", description));
  return n;
}
function toast(message) {
  $("toast").textContent = message;
  $("toast").hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => ($("toast").hidden = true), 5000);
}
function setAlert(message) {
  $("global-alert").hidden = !message;
  $("global-alert").textContent = message || "";
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${state.token}`,
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...options.headers,
    },
    cache: "no-store",
    signal: AbortSignal.timeout(15000),
  });
  const value = await response.json();
  if (!response.ok) {
    if (response.status === 401) {
      disconnect();
    }
    throw new Error([value.error, value.detail].filter(Boolean).join(" · "));
  }
  return value;
}
function showView(name) {
  if (!titles[name]) name = "overview";
  state.view = name;
  document
    .querySelectorAll(".view")
    .forEach((n) => (n.hidden = n.id !== `view-${name}`));
  document.querySelectorAll("[data-view]").forEach((n) => {
    n.classList.toggle("active", n.dataset.view === name);
    n.setAttribute("aria-current", n.dataset.view === name ? "page" : "false");
  });
  $("page-title").textContent = titles[name][0];
  $("page-description").textContent = titles[name][1];
  $("breadcrumb").textContent =
    name === "system"
      ? "Gateway health"
      : name[0].toUpperCase() + name.slice(1);
  history.replaceState(null, "", `#${name}`);
  if (name === "trust" && state.connected) loadHistory();
  if (name === "topology" && state.data)
    renderTopology(state.data.devices.filter((d) => !d.deleting));
}
function disconnect() {
  state.token = "";
  state.connected = false;
  state.stale = false;
  state.data = null;
  state.history = [];
  state.historyIp = null;
  document.body.classList.remove("stale");
  setAlert("");
  document.querySelectorAll("dialog[open]").forEach((d) => d.close());
  $("api-token").value = "";
  $("workspace-mode").textContent = "Authentication required";
  $("mode-badge").textContent = "DISCONNECTED";
  $("mode-badge").className = "badge neutral";
  $("last-updated").textContent = "Not connected";
  clearViews();
  $("connect-dialog").showModal();
}
function clearViews() {
  topologySignature = "";
  topologyPage = 0;
  [
    "metric-cards",
    "distribution",
    "attention-list",
    "recent-signals",
    "device-rows",
    "traffic-rows",
    "audit-rows",
    "intelligence",
    "system-cards",
    "system-details",
    "topology-devices",
    "topology-svg",
    "traffic-chart",
    "trust-chart",
  ].forEach((id) => replace(id));
  $("nav-count").textContent = "0";
  $("banner-title").textContent = "Your edge. Your rules.";
  $("banner-subtitle").textContent =
    "Connect to your gateway to see its current security posture.";
  $("pipeline-state").textContent = "○ Waiting for gateway";
}
async function refresh() {
  if (!state.token || state.fetching) return false;
  const requestToken = state.token;
  state.fetching = true;
  try {
    const data = await api("/dashboard");
    if (state.token !== requestToken) return false;
    state.data = data;
    state.stale = false;
    state.connected = true;
    document.body.classList.remove("stale");
    render();
    $("last-updated").textContent =
      `Updated ${new Date(data.updated_at * 1000).toLocaleTimeString()}`;
    const errors = [
      data.error,
      ...Object.entries(data.detection_errors).map(
        ([ip, error]) => `${ip}: ${error}`,
      ),
      data.capture?.error,
    ].filter(Boolean);
    setAlert(
      errors.length
        ? `Gateway needs attention · ${errors.join(" · ")}`
        : data.capture?.dropped
          ? `${num(data.capture.dropped)} capture packets dropped. Traffic windows may be incomplete.`
          : "",
    );
    return true;
  } catch (error) {
    if (state.token) {
      state.stale = true;
      const graph = $("topology-svg");
      if (graph && typeof graph.pauseAnimations === "function")
        graph.pauseAnimations();
      document.body.classList.add("stale");
      setAlert(
        `Connection lost or data unavailable. Displayed values may be stale. ${error.message}`,
      );
      $("last-updated").textContent = "Connection unavailable";
    }
    throw error;
  } finally {
    state.fetching = false;
  }
}
function metric(label, value, note, symbol) {
  const n = el("article", "metric");
  const l = el("div", "metric-label", label);
  l.append(el("span", "metric-symbol", symbol));
  n.append(l, el("div", "metric-value", value), el("div", "metric-note", note));
  return n;
}
function detailList(rows) {
  const n = el("div", "detail-list");
  rows.forEach(([key, value]) => {
    const row = el("div");
    row.append(el("span", "", key), el("b", "", value ?? "—"));
    n.append(row);
  });
  return n;
}
function updateSelect(id, items, allLabel) {
  const select = $(id),
    previous = select.value;
  const options = [];
  if (allLabel) {
    const o = el("option", "", allLabel);
    o.value = "";
    options.push(o);
  }
  items.forEach((d) => {
    const o = el("option", "", `${d.name} · ${d.ip}`);
    o.value = d.ip;
    options.push(o);
  });
  select.replaceChildren(...options);
  if (items.some((d) => d.ip === previous)) select.value = previous;
}
function render() {
  const d = state.data,
    active = d.devices.filter((x) => !x.deleting),
    pending = d.devices.filter(
      (x) => x.desired_tier !== x.applied_tier || x.deleting,
    );
  $("mode-badge").textContent =
    d.mode === "simulation" ? "SIMULATION" : "LIVE GATEWAY";
  $("mode-badge").className =
    `badge ${d.mode === "simulation" ? "amber" : "green"}`;
  $("workspace-mode").textContent =
    d.mode === "simulation"
      ? "Explicit simulation workspace"
      : "Raspberry Pi gateway";
  $("footer-mode").textContent =
    d.mode === "simulation"
      ? "Simulation · no live enforcement"
      : "Live · local enforcement";
  $("nav-count").textContent = active.length;
  $("banner-title").textContent = d.ready
    ? "Your edge is in focus."
    : "Your gateway needs attention.";
  $("banner-subtitle").textContent =
    d.mode === "simulation"
      ? "You are exploring an explicit simulation. Devices and decisions are local; real traffic is untouched."
      : d.ready
        ? "Local detection is running. Every policy decision stays on your Raspberry Pi."
        : "Review enforcement, detection, and capture health before relying on current policy.";
  $("pipeline-state").textContent =
    `${d.ready ? "●" : "○"} ${d.ready ? "Pipeline ready" : "Pipeline needs attention"}`;
  const quarantine = active.filter(
      (x) => x.applied_tier === "QUARANTINE",
    ).length,
    learning = active.filter((x) => x.learning).length;
  replace(
    "metric-cards",
    metric(
      "Enrolled devices",
      num(active.length),
      `${num(learning)} collecting a clean baseline`,
      "▦",
    ),
    metric(
      "Average trust",
      active.length
        ? num(
            (active.reduce((a, x) => a + x.trust, 0) / active.length) * 100,
            1,
          ) + "%"
        : "—",
      "Persisted per-device trust",
      "⌁",
    ),
    metric(
      "Quarantined",
      num(quarantine),
      "Confirmed enforcement restrictions",
      "◇",
    ),
    metric(
      "Pending policies",
      num(pending.length),
      "Desired differs from confirmed state",
      "⇄",
    ),
  );
  const windows = [...d.windows].reverse().slice(-24);
  drawChart(
    "traffic-chart",
    windows.map((w) => ({ value: w.packets, label: stamp(w.timestamp) })),
    "bar",
    null,
  );
  $("traffic-caption").textContent =
    `Latest ${windows.length} retained device windows · ${bytes(d.windows.reduce((n, w) => n + w.bytes, 0))} across the latest ${d.windows.length} windows`;
  renderDistribution(active);
  renderAttention(active);
  renderRecent();
  updateSelect("traffic-device", active, "All devices");
  updateSelect("trust-device", active, null);
  renderDevices();
  renderTraffic();
  renderAudit();
  renderSystem();
  renderTopology(active);
  renderIntelligence();
  if ($("device-dialog").open) renderInspector();
}
function renderDistribution(devices) {
  const counts = { TRUSTED: 0, CAUTIOUS: 0, QUARANTINE: 0, PENDING: 0 };
  devices.forEach((d) => counts[d.applied_tier || "PENDING"]++);
  const layout = el("div", "distribution-layout"),
    donut = el("div", "donut"),
    svg = sv("svg", { viewBox: "0 0 160 160" });
  svg.append(sv("circle", { cx: 80, cy: 80, r: 61, stroke: "#2a2d3a" }));
  let offset = 0;
  const length = 2 * Math.PI * 61;
  Object.entries(counts).forEach(([tier, count]) => {
    if (!count) return;
    const arc = (length * count) / devices.length;
    svg.append(
      sv("circle", {
        cx: 80,
        cy: 80,
        r: 61,
        stroke: colors[tier],
        "stroke-dasharray": `${arc} ${length - arc}`,
        "stroke-dashoffset": -offset,
      }),
    );
    offset += arc;
  });
  const center = el("div", "donut-center");
  center.append(
    el("strong", "", num(devices.length)),
    el("span", "", "DEVICES"),
  );
  donut.append(svg, center);
  const legend = el("div", "distribution-legend");
  Object.entries(counts).forEach(([tier, count]) => {
    const row = el("div", "distribution-row");
    const dot = sv("svg", { width: 7, height: 7, viewBox: "0 0 7 7" });
    dot.append(sv("circle", { cx: 3.5, cy: 3.5, r: 3, fill: colors[tier] }));
    row.append(
      dot,
      el(
        "span",
        "",
        tier === "PENDING"
          ? "Unconfirmed"
          : tier[0] + tier.slice(1).toLowerCase(),
      ),
      el("b", "", num(count)),
    );
    legend.append(row);
  });
  layout.append(donut, legend);
  replace("distribution", layout);
}
function renderAttention(devices) {
  const attention = devices
    .filter(
      (d) =>
        d.learning ||
        d.desired_tier !== d.applied_tier ||
        d.applied_tier !== "TRUSTED",
    )
    .slice(0, 4);
  replace(
    "attention-list",
    ...(attention.length
      ? attention.map((d) => {
          const n = el("button", "row-card row-button");
          const main = el("div", "row-main");
          main.append(
            el("strong", "", d.name),
            el(
              "small",
              "",
              `${d.ip} · ${d.learning ? `baseline ${d.baseline_count}/${d.baseline_required}` : "detection active"}`,
            ),
          );
          n.append(
            el("span", "device-icon", "▦"),
            main,
            badge(
              d.desired_tier !== d.applied_tier ? "PENDING" : d.applied_tier,
            ),
          );
          n.onclick = () => inspect(d.ip);
          return n;
        })
      : [
          empty(
            "Nothing needs attention",
            devices.length
              ? "All current device policies are confirmed."
              : "Enroll your first device to get started.",
          ),
        ]),
  );
}
function renderRecent() {
  const events = state.data.events
    .filter((e) => e.action !== "policy_applied" && e.action !== "window")
    .slice(0, 4);
  replace(
    "recent-signals",
    ...(events.length
      ? events.map((e) => {
          const n = el("div", "row-card");
          const main = el("div", "row-main");
          main.append(
            el("strong", "", human(e.action)),
            el("small", "", e.ip || "Gateway"),
          );
          n.append(
            el("span", "device-icon", e.action.includes("failed") ? "!" : "⌁"),
            main,
            el("time", "", stamp(e.timestamp)),
          );
          return n;
        })
      : [
          empty(
            "No lifecycle signals yet",
            "New decisions appear here as the gateway runs.",
          ),
        ]),
  );
}
function human(value) {
  return String(value)
    .replaceAll("_", " ")
    .replace(/^./, (s) => s.toUpperCase());
}
function renderDevices() {
  if (!state.data) return;
  const query = $("device-search").value.toLowerCase(),
    tier = $("tier-filter").value;
  const devices = state.data.devices.filter(
    (d) =>
      `${d.name} ${d.ip}`.toLowerCase().includes(query) &&
      (!tier ||
        (tier === "pending"
          ? d.desired_tier !== d.applied_tier || d.deleting
          : d.desired_tier === tier)),
  );
  const rows = devices.map((d) => {
    const row = el("tr"),
      identity = el("td");
    identity.append(
      el("strong", "", d.name),
      el("small", "", `${d.ip} · ${d.device_type}`),
    );
    const trust = el("td"),
      meter = el("div", "trust-meter"),
      progress = el("progress");
    progress.max = 1;
    progress.value = d.trust;
    progress.setAttribute(
      "aria-label",
      `${d.name} trust ${num(d.trust * 100, 1)}%`,
    );
    meter.append(progress, el("span", "", num(d.trust * 100, 1) + "%"));
    trust.append(meter);
    const desired = el("td"),
      applied = el("td");
    desired.append(badge(d.desired_tier));
    applied.append(badge(d.applied_tier));
    if (d.deleting) desired.append(el("small", "", "Deletion pending"));
    else if (d.desired_tier !== d.applied_tier)
      applied.append(el("small", "", "Enforcement pending"));
    const learning = el(
      "td",
      "",
      d.learning
        ? `${d.baseline_count} / ${d.baseline_required} windows`
        : "Baseline complete",
    );
    learning.append(
      el(
        "small",
        "",
        d.learning ? "Clean windows needed" : "Generation " + d.generation,
      ),
    );
    const action = el("td"),
      button = el("button", "text-button", "Inspect ↗");
    button.onclick = () => inspect(d.ip);
    action.append(button);
    row.append(
      identity,
      trust,
      desired,
      applied,
      learning,
      el("td", "", d.model_ready ? "Persisted" : "Not trained"),
      action,
    );
    return row;
  });
  replace(
    "device-rows",
    ...(rows.length
      ? rows
      : [
          emptyRow(7, "No matching devices. Enroll one or change the filters."),
        ]),
  );
}
function emptyRow(count, message) {
  const row = el("tr"),
    cell = el("td", "empty", message);
  cell.colSpan = count;
  row.append(cell);
  return row;
}
function renderTraffic() {
  if (!state.data) return;
  const ip = $("traffic-device").value,
    filter = $("signal-filter").value;
  const windows = state.data.windows.filter(
    (w) =>
      (!ip || w.ip === ip) &&
      (!filter ||
        (filter === "hard"
          ? w.hard
          : filter === "suppressed"
            ? w.ae_suppressed
            : typeof w.score === "number" && w.score >= 0.5)),
  );
  replace(
    "traffic-rows",
    ...(windows.length
      ? windows.map((w) => {
          const row = el("tr"),
            device = el("td");
          device.append(el("strong", "", w.name), el("small", "", w.ip));
          const amount = el("td", "", num(w.packets));
          amount.append(el("small", "", bytes(w.bytes)));
          const signal = el("td");
          signal.append(
            el(
              "span",
              `badge ${w.hard ? "red" : w.ae_suppressed ? "green" : "neutral"}`,
              w.hard
                ? w.reason
                : w.ae_suppressed
                  ? "AE suppressed"
                  : human(w.reason),
            ),
          );
          const policy = el("td");
          policy.append(badge(w.desired_tier));
          row.append(
            el("td", "", stamp(w.timestamp)),
            device,
            amount,
            signal,
            el("td", "", w.score === null ? "—" : num(w.score, 4)),
            el("td", "", num(w.trust * 100, 1) + "%"),
            policy,
          );
          return row;
        })
      : [
          emptyRow(
            7,
            "No matching windows. Traffic appears only after collection or an explicit simulation step.",
          ),
        ]),
  );
}
function renderAudit() {
  if (!state.data) return;
  const query = $("audit-search").value.toLowerCase(),
    filter = $("audit-filter").value;
  const events = state.data.events.filter(
    (e) =>
      JSON.stringify(e).toLowerCase().includes(query) &&
      (!filter ||
        (filter === "failure"
          ? e.action.includes("failed")
          : filter === "lifecycle"
            ? [
                "registered",
                "device_updated",
                "rebaseline",
                "deleted",
                "quarantine_release_requested",
                "phase1_model_imported",
              ].includes(e.action)
            : e.action === filter)),
  );
  replace(
    "audit-rows",
    ...(events.length
      ? events.map((e) => {
          const row = el("tr"),
            action = el("td");
          action.append(
            el(
              "span",
              `badge ${e.action.includes("failed") ? "red" : e.action === "tier_changed" ? "green" : "neutral"}`,
              human(e.action),
            ),
          );
          const detail = Object.entries(e)
            .filter(
              ([key]) => !["id", "timestamp", "action", "ip"].includes(key),
            )
            .map(
              ([key, v]) =>
                `${human(key)}: ${typeof v === "object" ? JSON.stringify(v) : v}`,
            )
            .join(" · ");
          row.append(
            el("td", "", stamp(e.timestamp)),
            action,
            el("td", "", e.ip || "Gateway"),
            el("td", "", detail || "—"),
          );
          return row;
        })
      : [emptyRow(4, "No matching audit events.")]),
  );
}
function renderSystem() {
  const d = state.data,
    h = d.health;
  replace(
    "system-cards",
    metric(
      "Process uptime",
      `${num(h.uptime_seconds / 3600, 1)} h`,
      "Since the local API process started",
      "◷",
    ),
    metric(
      "CPU load · 1 minute",
      num(h.load_average[0], 2),
      `${h.cpu_count} CPU cores · load, not utilization`,
      "⌁",
    ),
    metric(
      "Memory available",
      h.memory ? bytes(h.memory.available) : "—",
      h.memory
        ? `of ${bytes(h.memory.total)} system RAM`
        : "Available on Linux / Pi only",
      "▤",
    ),
    metric(
      "Pi temperature",
      h.temperature_c === null ? "—" : `${num(h.temperature_c, 1)} °C`,
      h.temperature_c === null
        ? "Thermal sensor unavailable"
        : "Local thermal sensor",
      "♧",
    ),
  );
  replace(
    "system-details",
    detailList([
      [
        "Runtime",
        d.mode === "simulation" ? "Explicit simulation" : "Live gateway",
      ],
      ["Pipeline", d.ready ? "Ready" : "Needs attention"],
      [
        "Capture",
        d.capture
          ? d.capture.running
            ? "Running"
            : "Stopped"
          : "Not started in simulation",
      ],
      [
        "Capture packets dropped",
        d.capture ? num(d.capture.dropped) : "Not applicable",
      ],
      ["Detector", d.detector],
      ["Storage free", bytes(h.disk.free)],
      ["LAN interface", d.topology?.lan || "Not supplied"],
      ["WAN interface", d.topology?.wan || "Not supplied"],
      [
        "Gateway / subnet",
        d.topology
          ? `${d.topology.gateway} · ${d.topology.subnet}`
          : "Hardware configuration not supplied",
      ],
    ]),
  );
}
// Phase 1 LAN → firewall → WAN layout, adapted to Phase 2's actual registry.
// Animation is illustrative; it never claims packet-level telemetry.
let topologyPage = 0;
let topologyPaused = false;
let topologySignature = "";
function renderTopology(devices) {
  const pageSize = 10;
  const pages = Math.max(1, Math.ceil(devices.length / pageSize));
  topologyPage = Math.min(topologyPage, pages - 1);
  const visible = devices.slice(
    topologyPage * pageSize,
    (topologyPage + 1) * pageSize,
  );
  const config = state.data.topology;
  const reducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;
  const paused =
    topologyPaused || reducedMotion || state.stale || !state.data.ready;
  $("topology-client-count").textContent =
    `${devices.length} enrolled · ${visible.length} shown`;
  $("topology-gateway").textContent = config
    ? `${config.gateway} · ${config.lan}`
    : "Local gateway";
  $("topology-wan").textContent = config
    ? `WAN: ${config.wan}`
    : "Upstream not configured";
  $("topology-page").textContent = `Page ${topologyPage + 1} / ${pages}`;
  $("topology-prev").disabled = topologyPage === 0;
  $("topology-next").disabled = topologyPage >= pages - 1;
  $("topology-motion").textContent = reducedMotion
    ? "Reduced motion enabled"
    : paused
      ? "Resume animation"
      : "Pause animation";
  $("topology-motion").disabled =
    reducedMotion || state.stale || !state.data.ready;
  $("topology-motion").setAttribute("aria-pressed", String(paused));
  const signature = JSON.stringify([
    visible,
    config,
    state.data.mode,
    state.data.ready,
    paused,
    topologyPage,
  ]);
  if (signature === topologySignature && $("topology-svg").childNodes.length) {
    const existing = $("topology-svg");
    if (!paused && typeof existing.unpauseAnimations === "function")
      existing.unpauseAnimations();
    return;
  }
  topologySignature = signature;
  const svg = $("topology-svg");
  svg.replaceChildren();
  if (typeof svg.unpauseAnimations === "function") svg.unpauseAnimations();
  const W = 1000,
    H = Math.max(500, visible.length * 76 + 130),
    cx = 515,
    cy = H / 2;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  function text(parent, value, x, y, options = {}) {
    const node = sv("text", {
      x,
      y,
      fill: "#e2e8f0",
      "font-size": 12,
      ...options,
    });
    node.textContent = value;
    parent.append(node);
    return node;
  }
  function zone(x, width, label, color) {
    svg.append(
      sv("rect", {
        x,
        y: 25,
        width,
        height: H - 50,
        rx: 15,
        fill: color,
        "fill-opacity": 0.04,
        stroke: color,
        "stroke-opacity": 0.23,
        "stroke-dasharray": "6 4",
      }),
    );
    text(svg, label, x + 17, 53, {
      fill: color,
      "font-size": 11,
      "letter-spacing": "1",
    });
  }
  zone(
    20,
    305,
    config ? `LAN · ${config.subnet}` : "LAN · ENROLLED DEVICES",
    "#818cf8",
  );
  zone(740, 240, "WAN · UPSTREAM", "#6366f1");
  const paths = sv("g"),
    dots = sv("g"),
    nodes = sv("g");
  svg.append(paths);
  function connection(path, color, index, blocked = false, uncertain = false) {
    paths.append(
      sv("path", {
        d: path,
        fill: "none",
        stroke: color,
        "stroke-width": 1.8,
        "stroke-opacity": 0.6,
        ...(blocked || uncertain ? { "stroke-dasharray": "6 5" } : {}),
      }),
    );
    if (!paused && !uncertain) {
      const dot = sv("circle", { r: 4, fill: color, opacity: 0.9 });
      dot.append(
        sv("animateMotion", {
          path,
          dur: `${2.2 + index * 0.17}s`,
          repeatCount: "indefinite",
          begin: "0s",
        }),
      );
      dots.append(dot);
    }
  }
  visible.forEach((device, index) => {
    const y = H / 2 - ((visible.length - 1) * 76) / 2 + index * 76;
    const pending = device.desired_tier !== device.applied_tier;
    const tier = device.applied_tier;
    const color = colors[tier] || colors.PENDING;
    const path = `M 303 ${y} C 365 ${y}, 411 ${cy}, 471 ${cy}`;
    connection(path, color, index, tier === "QUARANTINE", pending || !tier);
    const group = sv("g", {
      transform: `translate(41,${y - 29})`,
      tabindex: 0,
      role: "button",
      class: "topology-device-node",
      "aria-label": `${device.name}, ${device.ip}, confirmed ${tier || "unknown"}, trust ${num(device.trust * 100, 1)} percent. Inspect device.`,
    });
    group.append(
      sv("rect", {
        width: 262,
        height: 58,
        rx: 9,
        fill: "#1a1d27",
        stroke: color,
        "stroke-width": 1.5,
      }),
    );
    group.append(sv("rect", { width: 4, height: 58, rx: 2, fill: color }));
    const icon = device.device_type.includes("camera")
      ? "◉"
      : device.device_type === "printer"
        ? "▤"
        : device.device_type.includes("thermo")
          ? "♧"
          : "▦";
    text(group, icon, 15, 33, { fill: color, "font-size": 23 });
    const name =
      device.name.length > 20 ? device.name.slice(0, 19) + "…" : device.name;
    text(group, name, 48, 23, { "font-weight": 600, "font-size": 12 });
    text(group, device.ip, 48, 43, { fill: "#8892a4", "font-size": 10 });
    text(group, `${num(device.trust * 100)}%`, 247, 23, {
      fill: color,
      "text-anchor": "end",
      "font-size": 11,
    });
    text(
      group,
      pending
        ? "PENDING"
        : device.learning
          ? `LEARN ${device.baseline_count}/50`
          : tier || "UNKNOWN",
      247,
      43,
      {
        fill: pending ? "#f59e0b" : color,
        "text-anchor": "end",
        "font-size": 9,
      },
    );
    const title = sv("title");
    title.textContent = `${device.name} · ${device.ip} · desired ${device.desired_tier} / confirmed ${tier || "unknown"}`;
    group.append(title);
    group.onclick = () => inspect(device.ip);
    group.onkeydown = (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        inspect(device.ip);
      }
    };
    nodes.append(group);
    if (tier === "QUARANTINE")
      text(svg, "×", 451, cy - 12, { fill: "#ef4444", "font-size": 23 });
  });
  // Only confirmed, non-quarantined devices illustrate onward WAN policy paths.
  const onward = visible.some(
    (d) =>
      d.applied_tier &&
      d.applied_tier !== "QUARANTINE" &&
      d.applied_tier === d.desired_tier,
  );
  connection(
    `M 559 ${cy} C 625 ${cy}, 677 ${cy}, 776 ${cy}`,
    "#6366f1",
    4,
    !onward,
    !onward,
  );
  const fw = sv("g", { transform: `translate(${cx},${cy})` });
  fw.append(
    sv("circle", {
      r: 55,
      fill: "#534AB7",
      "fill-opacity": 0.1,
      stroke: "#6366f1",
      "stroke-opacity": 0.3,
    }),
  );
  fw.append(
    sv("circle", {
      r: 43,
      fill: "#22263a",
      stroke: "#6366f1",
      "stroke-width": 2.5,
    }),
  );
  fw.append(
    sv("path", {
      d: "M12 22s-8-4-8-10V5l8-3 8 3v7c0 6-8 10-8 10z",
      transform: "translate(-17,-21) scale(1.4)",
      fill: "none",
      stroke: "#a5b4fc",
      "stroke-width": 1.5,
    }),
  );
  text(fw, "FIREWALL", 0, 79, {
    fill: "#a5b4fc",
    "text-anchor": "middle",
    "font-weight": 700,
    "letter-spacing": "2",
  });
  text(fw, "TrustEdge · Raspberry Pi", 0, 99, {
    fill: "#8892a4",
    "text-anchor": "middle",
    "font-size": 10,
  });
  text(fw, "LOCAL TRUST + ML", 0, 117, {
    fill: "#818cf8",
    "text-anchor": "middle",
    "font-size": 9,
  });
  nodes.append(fw);
  const wan = sv("g", { transform: `translate(776,${cy - 32})` });
  wan.append(
    sv("rect", {
      width: 170,
      height: 64,
      rx: 10,
      fill: "#1a1d27",
      stroke: "#6366f1",
    }),
  );
  text(wan, "◎", 14, 39, { fill: "#818cf8", "font-size": 26 });
  text(wan, config ? "Upstream router" : "Logical upstream", 48, 26, {
    "font-size": 11,
  });
  text(wan, config ? `via ${config.wan}` : "Not configured", 48, 46, {
    fill: "#8892a4",
    "font-size": 10,
  });
  nodes.append(wan);
  svg.append(dots, nodes);
  if (!devices.length)
    text(svg, "Enroll a device to build your network map", 172, cy, {
      fill: "#8892a4",
      "text-anchor": "middle",
      "font-size": 11,
    });
  text(
    svg,
    state.data.mode === "simulation"
      ? "SIMULATION · ILLUSTRATIVE FLOW"
      : "LOGICAL POLICY PATHS · NOT PACKET TELEMETRY",
    cx,
    H - 30,
    { fill: "#8892a4", "text-anchor": "middle", "font-size": 10 },
  );
  replace("topology-devices");
}
$("topology-motion").onclick = () => {
  topologyPaused = !topologyPaused;
  renderTopology(state.data.devices.filter((d) => !d.deleting));
};
$("topology-prev").onclick = () => {
  topologyPage = Math.max(0, topologyPage - 1);
  renderTopology(state.data.devices.filter((d) => !d.deleting));
};
$("topology-next").onclick = () => {
  topologyPage++;
  renderTopology(state.data.devices.filter((d) => !d.deleting));
};
function renderIntelligence() {
  const d = state.data?.devices.find((d) => d.ip === $("trust-device").value);
  replace(
    "intelligence",
    d
      ? detailList([
          ["Device", d.name],
          ["Baseline progress", `${d.baseline_count} / ${d.baseline_required}`],
          [
            "Isolation Forest",
            d.model_ready ? "Persisted locally" : "Not trained",
          ],
          [
            "Autoencoder",
            d.model_info?.autoencoder
              ? "Trained locally / imported"
              : "Waiting for 15 clean detection windows",
          ],
          ["Rolling clean windows", `${d.rolling_count} / 50`],
          ["Adaptive threshold", num(d.threshold, 2)],
          [
            "Collected signatures",
            `${d.signature_count} · ${d.signature_complete ? "complete" : "collecting"}`,
          ],
          [
            "Anomaly / recovery streak",
            `${d.anomaly_streak || 0} / ${d.normal_streak || 0}`,
          ],
          ["Baseline generation", d.generation],
        ])
      : empty("Select an enrolled device"),
  );
}
function sv(tag, attrs = {}) {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, String(v)));
  return n;
}
function drawChart(id, points, type, max) {
  if (!points.length) {
    replace(
      id,
      empty(
        "No observations yet",
        "Charts show retained gateway windows, never generated placeholder data.",
      ),
    );
    return;
  }
  const svg = sv("svg", {
      viewBox: "0 0 600 180",
      role: "img",
      "aria-label":
        type === "bar"
          ? "Observed packet count per capture window"
          : "Persisted trust scores by capture window",
    }),
    ceiling = max || Math.max(...points.map((x) => x.value), 1),
    x = (i) => 42 + (i * 540) / Math.max(1, points.length - 1),
    y = (v) => 145 - (v / ceiling) * 125;
  for (let i = 0; i < 4; i++) {
    const value = (ceiling * i) / 3;
    svg.append(
      sv("line", {
        x1: 40,
        x2: 588,
        y1: y(value),
        y2: y(value),
        class: "grid-line",
      }),
    );
    const text = sv("text", { x: 31, y: y(value) + 4, "text-anchor": "end" });
    text.textContent = max ? num(value * 100) + "%" : num(value);
    svg.append(text);
  }
  if (type === "bar") {
    const width = Math.min(24, 470 / points.length);
    points.forEach((p, i) => {
      const bar = sv("rect", {
        x: points.length === 1 ? 300 : x(i) - width / 2,
        y: y(p.value),
        width,
        height: Math.max(1, 145 - y(p.value)),
        rx: 3,
        class: "bar",
      });
      const title = sv("title");
      title.textContent = `${p.label}: ${num(p.value)} packets`;
      bar.append(title);
      svg.append(bar);
    });
  } else {
    const path = points
      .map((p, i) => `${i ? "L" : "M"}${x(i)},${y(p.value)}`)
      .join(" ");
    svg.append(
      sv("path", {
        d: `${path} L${x(points.length - 1)},145 L42,145 Z`,
        class: "trust-area",
      }),
      sv("path", { d: path, class: "trust-line" }),
    );
    points.forEach((p, i) => {
      const dot = sv("circle", {
        cx: x(i),
        cy: y(p.value),
        r: 3,
        fill: "#22c55e",
      });
      const title = sv("title");
      title.textContent = `${p.label}: ${num(p.value * 100, 1)}%`;
      dot.append(title);
      svg.append(dot);
    });
  }
  const start = sv("text", { x: 42, y: 170 }),
    end = sv("text", { x: 582, y: 170, "text-anchor": "end" });
  start.textContent = points[0].label;
  end.textContent = points.at(-1).label;
  svg.append(start, end);
  replace(id, svg);
}
async function loadHistory() {
  const ip = $("trust-device").value;
  renderIntelligence();
  if (!ip) {
    state.history = [];
    state.historyIp = null;
    drawChart("trust-chart", [], "line", 1);
    return;
  }
  try {
    const history = await api(
      `/devices/${encodeURIComponent(ip)}/history?limit=300`,
    );
    if ($("trust-device").value !== ip) return;
    state.history = history;
    state.historyIp = ip;
    const device = state.data.devices.find((d) => d.ip === ip),
      points = history
        .filter((w) => w.generation === device.generation)
        .reverse();
    drawChart(
      "trust-chart",
      points.map((w) => ({ value: w.trust, label: stamp(w.timestamp) })),
      "line",
      1,
    );
    $("trust-caption").textContent =
      `${device.name} · generation ${device.generation} · ${points.length} retained observations · score range 0–100%`;
  } catch (e) {
    toast(e.message);
  }
}
function inspect(ip) {
  state.selected = ip;
  renderInspector();
  if (!$("device-dialog").open) $("device-dialog").showModal();
}
function renderInspector() {
  const d = state.data?.devices.find((x) => x.ip === state.selected);
  if (!d) {
    $("device-dialog").close();
    return;
  }
  $("detail-title").textContent = d.name;
  const list = detailList([
    ["Reserved IPv4", d.ip],
    ["Profile", d.device_type],
    ["Trust", num(d.trust * 100, 1) + "%"],
    ["Desired policy", d.desired_tier],
    ["Last confirmed policy", d.applied_tier || "UNCONFIRMED"],
    [
      "Learning",
      d.learning
        ? `${d.baseline_count} / ${d.baseline_required} clean windows`
        : "Baseline complete",
    ],
    ["Isolation Forest", d.model_ready ? "Persisted locally" : "Not trained"],
    [
      "Autoencoder",
      d.model_info?.autoencoder
        ? "Trained locally / imported"
        : "Waiting for 15 clean detection windows",
    ],
    ["Allowed destinations", d.destinations.join(", ") || "None configured"],
    ["Signature threshold", num(d.threshold, 2)],
    ["Signatures collected", d.signature_count],
    [
      "Consecutive anomalous windows",
      `${d.anomaly_streak || 0} (3 required for a downgrade)`,
    ],
    [
      "Enforcement",
      d.deleting
        ? "Deletion pending"
        : d.desired_tier !== d.applied_tier
          ? "Pending / unconfirmed"
          : "Last operation confirmed",
    ],
  ]);
  const latest = state.data.windows.find((w) => w.ip === d.ip),
    nodes = [list];
  if (latest) {
    nodes.push(el("h3", "", "Latest feature vector"));
    const grid = el("div", "feature-grid");
    state.data.feature_names.forEach((name, i) => {
      const row = el("div");
      row.append(
        el("span", "", human(name)),
        el("b", "", num(latest.features[i], 4)),
      );
      grid.append(row);
    });
    nodes.push(grid);
  }
  replace("device-detail", ...nodes);
  $("release-device").disabled = d.desired_tier !== "QUARANTINE" || d.deleting;
  ["edit-device", "rebaseline-device", "delete-device"].forEach(
    (id) => ($(id).disabled = !!d.deleting),
  );
  $("simulation-actions").hidden =
    state.data.mode !== "simulation" || d.deleting;
}
function destinationList(value) {
  return value
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
}
function openAction(action) {
  const d = state.data.devices.find((x) => x.ip === state.selected);
  if (!d) return;
  const configs = {
    edit: [
      "Edit device destinations",
      "CAUTIOUS policy allows HTTP/HTTPS only to these IPv4 destinations, plus configured DNS. Changes are applied through checked local enforcement.",
    ],
    rebaseline: [
      "Start a fresh baseline",
      "This clears the model, baseline, signatures, and streaks. Trust and quarantine are preserved; a trusted device becomes CAUTIOUS while relearning.",
    ],
    release: [
      "Release quarantine",
      "This is an explicit operator override to CAUTIOUS at 55% trust. It does not grant unrestricted access or clear the model. Record why this device is safe to release.",
    ],
    delete: [
      "Remove device",
      "The device and its model/history are removed only after policy cleanup succeeds. Its address stays blocked as an unknown device. Audit records remain.",
    ],
  };
  $("action-title").textContent = configs[action][0];
  $("action-description").textContent =
    `${d.name} (${d.ip}) · ${configs[action][1]}`;
  replace("action-fields");
  if (action === "edit") {
    [
      ["Name", "name", d.name, false],
      [
        "Destination IPv4 addresses",
        "destinations",
        d.destinations.join("\n"),
        true,
      ],
    ].forEach(([label, name, value, multi]) => {
      const l = el("label", "", label),
        input = el(multi ? "textarea" : "input");
      input.name = name;
      input.value = value;
      if (multi) input.rows = 4;
      else {
        input.required = true;
        input.maxLength = 80;
      }
      l.append(input);
      $("action-fields").append(l);
    });
  }
  if (action === "release") {
    const label = el("label", "", "Release reason"),
      input = el("textarea");
    input.name = "reason";
    input.minLength = 5;
    input.maxLength = 300;
    input.required = true;
    input.rows = 3;
    label.append(input);
    $("action-fields").append(label);
  }
  $("action-error").textContent = "";
  $("action-submit").textContent =
    action === "delete"
      ? "Remove device"
      : action === "edit"
        ? "Save changes"
        : "Confirm";
  $("action-dialog").dataset.action = action;
  $("action-dialog").dataset.ip = d.ip;
  $("action-dialog").showModal();
}
async function performAction(event) {
  event.preventDefault();
  const dialog = $("action-dialog"),
    action = dialog.dataset.action,
    ip = dialog.dataset.ip,
    form = new FormData($("action-form"));
  let path = `/devices/${encodeURIComponent(ip)}`,
    method = "POST",
    body;
  if (action === "edit") {
    method = "PATCH";
    body = {
      name: form.get("name"),
      destinations: destinationList(form.get("destinations")),
    };
  } else if (action === "delete") method = "DELETE";
  else {
    path += `/${action === "release" ? "release" : "rebaseline"}`;
    body = action === "release" ? { reason: form.get("reason") } : {};
  }
  $("action-submit").disabled = true;
  try {
    await api(path, {
      method,
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    dialog.close();
    await refresh();
    if (action === "delete") $("device-dialog").close();
    toast("Gateway action completed and enforcement confirmed.");
  } catch (e) {
    $("action-error").textContent = e.message;
    await refresh().catch(() => {});
  } finally {
    $("action-submit").disabled = false;
  }
}
async function simulate(attack) {
  const ip = state.selected;
  const buttons = [$("simulate-normal"), $("simulate-attack")];
  buttons.forEach((b) => (b.disabled = true));
  try {
    await api(`/devices/${encodeURIComponent(ip)}/simulate`, {
      method: "POST",
      body: JSON.stringify({ attack }),
    });
    await refresh();
    toast(
      attack
        ? "Simulated scan processed. No network packets were sent."
        : "One normal simulation window processed.",
    );
  } catch (e) {
    toast(e.message);
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}
function download(name, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], {
      type: "application/json",
    }),
    url = URL.createObjectURL(blob),
    a = el("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$("connect-form").onsubmit = async (event) => {
  event.preventDefault();
  state.token = $("api-token").value.trim();
  $("connect-error").textContent = "";
  const button = event.submitter;
  button.disabled = true;
  try {
    const refreshed = await refresh();
    if (!refreshed)
      throw new Error(
        "A gateway request is still finishing. Please connect again in a moment.",
      );
    $("api-token").value = "";
    $("connect-dialog").close();
    if (state.view === "trust") loadHistory();
  } catch (e) {
    $("connect-error").textContent = e.message;
    state.token = "";
  } finally {
    button.disabled = false;
  }
};
$("connect-dialog").addEventListener("cancel", (e) => e.preventDefault());
$("disconnect").onclick = disconnect;
$("refresh").onclick = () =>
  refresh()
    .then(() => {
      if (state.view === "trust") loadHistory();
    })
    .catch(() => {});
$("pause").onclick = () => {
  state.paused = !state.paused;
  $("pause").textContent = state.paused ? "Resume updates" : "Pause updates";
};
document
  .querySelectorAll("[data-view]")
  .forEach((b) => (b.onclick = () => showView(b.dataset.view)));
document
  .querySelectorAll("[data-go]")
  .forEach((b) => (b.onclick = () => showView(b.dataset.go)));
document
  .querySelectorAll("[data-close]")
  .forEach((b) => (b.onclick = () => $(b.dataset.close).close()));
$("add-device").onclick = () => {
  if (!state.connected) return;
  $("enroll-error").textContent = "";
  $("enroll-dialog").showModal();
};
const profiles = {
  custom: 5,
  laptop: 8,
  "iot-camera": 6,
  "iot-thermo": 2,
  smartphone: 5,
  printer: 1,
  "smart-lock": 1,
  "smart-hub": 4,
  nas: 10,
  "voip-phone": 7,
};
Object.keys(profiles).forEach((p) => {
  const option = el("option", "", human(p));
  option.value = p;
  $("device-type").append(option);
});
$("device-type").onchange = () => {
  $("enroll-form").elements.rate.value = profiles[$("device-type").value];
};
$("enroll-form").onsubmit = async (e) => {
  e.preventDefault();
  const form = new FormData(e.target),
    button = e.submitter;
  button.disabled = true;
  try {
    await api("/devices", {
      method: "POST",
      body: JSON.stringify({
        name: form.get("name"),
        ip: form.get("ip"),
        device_type: form.get("device_type"),
        rate: Number(form.get("rate")),
        destinations: destinationList(form.get("destinations")),
      }),
    });
    $("enroll-dialog").close();
    e.target.reset();
    await refresh();
    toast("Device enrolled. CAUTIOUS policy confirmed.");
  } catch (error) {
    $("enroll-error").textContent = error.message;
    await refresh().catch(() => {});
  } finally {
    button.disabled = false;
  }
};
$("device-search").oninput = renderDevices;
$("tier-filter").onchange = renderDevices;
$("traffic-device").onchange = renderTraffic;
$("signal-filter").onchange = renderTraffic;
$("audit-search").oninput = renderAudit;
$("audit-filter").onchange = renderAudit;
$("trust-device").onchange = loadHistory;
$("load-history").onclick = loadHistory;
$("edit-device").onclick = () => openAction("edit");
$("rebaseline-device").onclick = () => openAction("rebaseline");
$("release-device").onclick = () => openAction("release");
$("delete-device").onclick = () => openAction("delete");
$("action-form").onsubmit = performAction;
$("simulate-normal").onclick = () => simulate(false);
$("simulate-attack").onclick = () => simulate(true);
$("export-windows").onclick = () => {
  if (state.data)
    download("trustedge-retained-windows.json", state.data.windows);
};
$("export-events").onclick = () => {
  if (state.data) download("trustedge-audit.json", state.data.events);
};
setInterval(() => {
  if (state.connected && !state.paused && !document.hidden)
    refresh()
      .then(() => {
        if (state.view === "trust") loadHistory();
      })
      .catch(() => {});
}, 5000);
window.addEventListener("hashchange", () =>
  showView(location.hash.slice(1) || "overview"),
);
const pairingCode = new URLSearchParams(location.hash.slice(1)).get("pair");
// Remove the single-use pairing fragment before requests, navigation or polling.
if (pairingCode)
  history.replaceState(null, "", location.pathname + location.search);
showView(location.hash.slice(1) || "overview");
$("connect-dialog").showModal();
async function autoPair(code) {
  try {
    const response = await fetch("/session/pair", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
      cache: "no-store",
      signal: AbortSignal.timeout(15000),
    });
    const result = await response.json();
    if (!response.ok)
      throw new Error(result.error || "Automatic sign-in failed");
    state.token = result.token;
    if (!(await refresh()))
      throw new Error("Automatic sign-in could not complete");
    $("connect-dialog").close();
  } catch (error) {
    state.token = "";
    $("connect-error").textContent =
      error.message + ". Restart the dashboard launcher to try again.";
  }
}
if (pairingCode) autoPair(pairingCode);
