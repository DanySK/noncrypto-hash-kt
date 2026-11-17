"use strict";

/*
 * Renders the runs in window.BENCHMARK_RUNS (written by `./gradlew benchmark`), newest first.
 * Speed: one small multiple per target, with its own linear axis, since targets differ by orders of magnitude.
 * Algorithms keep the same color in every chart: color follows the algorithm, never its rank.
 */

const RUNS = window.BENCHMARK_RUNS || [];
const TARGET_ORDER = ["jvm", "js", "wasmJs", "wasmWasi", "native"];
const TARGET_NAMES = { jvm: "JVM", js: "JavaScript", wasmJs: "Wasm (JS)", wasmWasi: "Wasm (WASI)", native: "Native" };
const SERIES_SLOTS = 8;
const BULK_BYTES = 1024;
const REPOSITORY = "https://github.com/DanySK/noncrypto-hash-kt";

const state = { run: RUNS[0], workload: null };

const $ = (id) => document.getElementById(id);

function element(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
  children.flat().forEach((child) => node.append(child instanceof Node ? child : document.createTextNode(String(child))));
  return node;
}

function svgElement(tag, attributes = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  Object.entries(attributes).forEach(([key, value]) => node.setAttribute(key, value));
  return node;
}

function formatNumber(value, digits = 3) {
  return Number(value).toLocaleString("en-US", { maximumSignificantDigits: digits });
}

function formatTime(nanos) {
  if (nanos == null) return "–";
  if (nanos < 1e3) return `${formatNumber(nanos)} ns`;
  if (nanos < 1e6) return `${formatNumber(nanos / 1e3)} µs`;
  return `${formatNumber(nanos / 1e6)} ms`;
}

function formatThroughput(bytesPerSecond) {
  if (bytesPerSecond == null) return "–";
  if (bytesPerSecond >= 1e9) return `${formatNumber(bytesPerSecond / 1e9)} GB/s`;
  return `${formatNumber(bytesPerSecond / 1e6)} MB/s`;
}

function formatBytes(bytes) {
  if (bytes == null) return "–";
  if (bytes >= 1024 ** 3) return `${formatNumber(bytes / 1024 ** 3)} GiB`;
  return `${formatNumber(bytes, 4)} B`;
}

function targetsOf(run) {
  return [...run.targets].sort((a, b) => TARGET_ORDER.indexOf(a.target) - TARGET_ORDER.indexOf(b.target));
}

function algorithmsOf(run) {
  const names = [];
  run.targets.forEach((target) => target.results.forEach((result) => {
    if (!names.includes(result.algorithm)) names.push(result.algorithm);
  }));
  return names;
}

function workloadsOf(run) {
  const workloads = [];
  run.targets.forEach((target) => target.results.forEach((result) => {
    if (!workloads.some((workload) => workload.id === result.workload)) {
      workloads.push({
        id: result.workload,
        label: result.label,
        inputBytes: result.inputBytes,
        // Older results have no bulk flag: bulk was implied by the input size
        bulk: result.bulk ?? result.inputBytes >= BULK_BYTES,
      });
    }
  }));
  return workloads;
}

function seriesColor(run, algorithm) {
  const slot = algorithmsOf(run).indexOf(algorithm) % SERIES_SLOTS;
  return `var(--series-${slot + 1})`;
}

/* Small inputs and structured values: time per operation. Bulk inputs: throughput. */
function metricFor(workload) {
  if (workload.bulk) {
    return {
      description: "Throughput, median of the measured batches. Higher is better.",
      value: (result) => result.bytesPerSecond,
      format: formatThroughput,
    };
  }
  return {
    description: "Time per operation, median of the measured batches. Lower is better.",
    value: (result) => result.nsPerOp.median,
    format: formatTime,
  };
}

function renderRunSelector() {
  const select = $("run");
  select.replaceChildren(...RUNS.map((run, index) => {
    return element("option", { value: String(index) }, runLabel(run));
  }));
  select.addEventListener("change", () => {
    state.run = RUNS[Number(select.value)];
    state.workload = null;
    render();
  });
}

/**
 * "version (dirty) - ISO date - CPU", where runs older than the version field omit the version.
 */
function runLabel(run) {
  const version = run.version ? [`${run.version}${run.commit.dirty ? " (dirty)" : ""}`] : [];
  const date = new Date(run.date).toISOString().replace(/\.\d+Z$/, "Z");
  return [...version, date, run.machine.cpu].join(" - ") + (run.quick ? " (quick)" : "");
}

function renderSummary(run) {
  const machine = run.machine;
  const commit = run.commit.hash
    ? element("a", { href: `${REPOSITORY}/commit/${run.commit.hash}` }, run.commit.hash.slice(0, 10))
    : "unknown";
  const machineCard = element("div", { class: "card" },
    element("h3", {}, "Machine"),
    element("dl", {},
      element("dt", {}, "Label"), element("dd", {}, machine.label),
      element("dt", {}, "CPU"), element("dd", {}, machine.cpu),
      element("dt", {}, "Cores"), element("dd", {}, String(machine.cores)),
      element("dt", {}, "Memory"), element("dd", {}, formatBytes(machine.memoryBytes)),
      element("dt", {}, "OS"), element("dd", {}, `${machine.os} ${machine.osVersion} (${machine.arch})`),
    ),
  );
  const runCard = element("div", { class: "card" },
    element("h3", {}, "Run"),
    element("dl", {},
      element("dt", {}, "Version"), element("dd", {}, run.version || "unknown"),
      element("dt", {}, "Date"), element("dd", {}, new Date(run.date).toLocaleString()),
      element("dt", {}, "Commit"), element("dd", {}, commit, run.commit.dirty ? " (uncommitted changes)" : ""),
      element("dt", {}, "Kotlin"), element("dd", {}, run.kotlin),
      ...targetsOf(run).flatMap((target) => [
        element("dt", {}, TARGET_NAMES[target.target] || target.target),
        element("dd", {}, target.runtime),
      ]),
    ),
  );
  const children = [element("div", { class: "summary" }, machineCard, runCard)];
  if (run.quick) {
    children.unshift(element("p", { class: "notice" }, "Quick run: short warmup and few rounds. Not representative."));
  }
  $("summary").replaceChildren(...children);
}

function renderWorkloadButtons(run) {
  const workloads = workloadsOf(run);
  if (!state.workload || !workloads.some((workload) => workload.id === state.workload.id)) {
    state.workload = workloads[0];
  }
  $("workloads").replaceChildren(...workloads.map((workload) => {
    const button = element("button", { type: "button", "aria-pressed": String(workload.id === state.workload.id) }, workload.label);
    button.addEventListener("click", () => {
      state.workload = workload;
      render();
    });
    return button;
  }));
}

function showTooltip(event, lines) {
  const tooltip = $("tooltip");
  tooltip.replaceChildren(...lines.map(([text, muted]) => element("div", muted ? { class: "muted" } : {}, text)));
  tooltip.hidden = false;
  const margin = 12;
  const { width, height } = tooltip.getBoundingClientRect();
  const x = Math.min(event.clientX + margin, window.innerWidth - width - margin);
  const y = Math.min(event.clientY + margin, window.innerHeight - height - margin);
  tooltip.style.left = `${Math.max(margin, x)}px`;
  tooltip.style.top = `${Math.max(margin, y)}px`;
}

function hideTooltip() {
  $("tooltip").hidden = true;
}

function niceTicks(max, count = 3) {
  const raw = max / count;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((factor) => factor * magnitude).find((candidate) => candidate >= raw);
  const ticks = [];
  for (let tick = 0; tick <= max + step / 2; tick += step) ticks.push(tick);
  return ticks;
}

/* Horizontal bars, one per algorithm, on a linear axis starting at zero. */
function renderPanel(run, target, workload, metric, width) {
  const results = target.results.filter((result) => result.workload === workload.id);
  const panel = element("div", { class: "panel" },
    element("h3", {}, TARGET_NAMES[target.target] || target.target),
    element("p", { class: "runtime" }, target.runtime),
  );
  if (results.length === 0) {
    panel.append(element("p", { class: "empty" }, "No data"));
    return panel;
  }
  const labelWidth = 120;
  const valueWidth = 76;
  const rowHeight = 32;
  const barHeight = 20;
  const axisHeight = 22;
  const plotWidth = Math.max(60, width - labelWidth - valueWidth);
  const height = results.length * rowHeight + axisHeight;
  const ticks = niceTicks(Math.max(...results.map(metric.value)));
  const scale = (value) => (value / ticks[ticks.length - 1]) * plotWidth;
  const svg = svgElement("svg", { viewBox: `0 0 ${width} ${height}`, height: String(height), role: "img" });
  svg.setAttribute("aria-label", `${workload.label} on ${TARGET_NAMES[target.target] || target.target}`);
  ticks.forEach((tick) => {
    const x = labelWidth + scale(tick);
    svg.append(svgElement("line", { class: "gridline", x1: x, x2: x, y1: 0, y2: results.length * rowHeight }));
    const label = svgElement("text", { x, y: height - 4, "text-anchor": "middle" });
    label.textContent = metric.format(tick).replace(/^0 \S+$/, "0");
    svg.append(label);
  });
  results.forEach((result, index) => {
    const y = index * rowHeight + (rowHeight - barHeight) / 2;
    const length = Math.max(1, scale(metric.value(result)));
    const radius = Math.min(4, length);
    const name = svgElement("text", { x: labelWidth - 8, y: y + barHeight / 2 + 4, "text-anchor": "end" });
    name.textContent = result.algorithm;
    // Square at the baseline, rounded at the data end
    const bar = svgElement("path", {
      d: `M${labelWidth},${y} h${length - radius} a${radius},${radius} 0 0 1 ${radius},${radius} v${barHeight - 2 * radius} a${radius},${radius} 0 0 1 ${-radius},${radius} h${-(length - radius)} z`,
      fill: seriesColor(run, result.algorithm),
    });
    const value = svgElement("text", { class: "value", x: labelWidth + length + 6, y: y + barHeight / 2 + 4 });
    value.textContent = metric.format(metric.value(result));
    const hit = svgElement("rect", { class: "hit", x: 0, y: index * rowHeight, width, height: rowHeight });
    const lines = [
      [`${result.algorithm} · ${TARGET_NAMES[target.target] || target.target}`],
      [`${workload.label}: ${formatTime(result.nsPerOp.median)} per operation`],
      [`Range ${formatTime(result.nsPerOp.min)} – ${formatTime(result.nsPerOp.max)}`, true],
      [`Throughput ${formatThroughput(result.bytesPerSecond)}`, true],
    ];
    if (result.allocatedBytesPerOp != null) lines.push([`Allocated ${formatBytes(result.allocatedBytesPerOp)} per operation`, true]);
    hit.addEventListener("mousemove", (event) => showTooltip(event, lines));
    hit.addEventListener("mouseleave", hideTooltip);
    svg.append(name, bar, value, hit);
  });
  panel.append(svg);
  return panel;
}

function renderSpeed(run) {
  const workload = state.workload;
  const metric = metricFor(workload);
  $("metric").textContent = `${workload.label}: ${metric.description}`;
  const algorithms = algorithmsOf(run);
  // A single series needs no legend: the bar labels name it
  $("legend").replaceChildren(...(algorithms.length >= 2 ? algorithms.map((algorithm) => element("span", {},
    element("span", { class: "swatch", style: `background: ${seriesColor(run, algorithm)}` }), algorithm)) : []));
  const container = $("panels");
  container.replaceChildren();
  const panels = targetsOf(run).map((target) => {
    const panel = element("div", { class: "panel" });
    container.append(panel);
    return [target, panel];
  });
  // Measure the panel width once it is in the layout
  const width = Math.max(240, Math.floor((panels[0]?.[1].clientWidth || 300) - 32));
  panels.forEach(([target, placeholder]) => placeholder.replaceWith(renderPanel(run, target, workload, metric, width)));
}

function table(headers, rows) {
  return element("table", {},
    element("thead", {}, element("tr", {}, headers.map(([text, numeric]) => element("th", numeric ? { class: "number" } : {}, text)))),
    element("tbody", {}, rows.map((row) => element("tr", {}, row.map(([text, numeric]) => element("td", numeric ? { class: "number" } : {}, text))))),
  );
}

function renderFootprints(run) {
  const targets = targetsOf(run);
  const rows = algorithmsOf(run).map((algorithm) => [
    [algorithm],
    ...targets.map((target) => {
      const footprint = target.footprints.find((entry) => entry.algorithm === algorithm);
      if (!footprint || footprint.bytesPerDigest == null) return ["n/a", true];
      const approximate = footprint.method === "allocation counter" ? "" : "≈ ";
      const bytes = approximate ? Math.round(footprint.bytesPerDigest) : footprint.bytesPerDigest;
      return [`${approximate}${formatBytes(bytes)}`, true];
    }),
  ]);
  $("footprints").replaceChildren(table([["Algorithm"], ...targets.map((target) => [TARGET_NAMES[target.target] || target.target, true])], rows));
}

function renderAll(run) {
  const rows = targetsOf(run).flatMap((target) => target.results.map((result) => [
    [result.label],
    [result.algorithm],
    [TARGET_NAMES[target.target] || target.target],
    [formatTime(result.nsPerOp.median), true],
    [`${formatTime(result.nsPerOp.min)} – ${formatTime(result.nsPerOp.max)}`, true],
    [formatThroughput(result.bytesPerSecond), true],
    [result.allocatedBytesPerOp == null ? "n/a" : formatBytes(result.allocatedBytesPerOp), true],
  ]));
  $("all").replaceChildren(table([
    ["Workload"], ["Algorithm"], ["Target"], ["Median", true], ["Range", true], ["Throughput", true], ["Allocated per op", true],
  ], rows));
}

function render() {
  const run = state.run;
  if (!run) {
    $("summary").replaceChildren(element("p", { class: "notice" }, "No results yet: run ./gradlew benchmark"));
    return;
  }
  renderSummary(run);
  renderWorkloadButtons(run);
  renderSpeed(run);
  renderFootprints(run);
  renderAll(run);
}

renderRunSelector();
render();
let resizeTimer;
window.addEventListener("resize", () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => state.run && renderSpeed(state.run), 150);
});
