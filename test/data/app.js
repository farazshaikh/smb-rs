// Renders test/data/results.json produced by smb-testrunner. No build step,
// no server: open index.html directly or serve the folder statically.

const $ = (sel) => document.querySelector(sel);

function fmtDate(epoch) {
  return new Date(epoch * 1000).toISOString().replace("T", " ").replace(".000Z", "Z");
}

function pill(status) {
  return `<span class="pill ${status}">${status}</span>`;
}

function card(n, label, color) {
  return `<div class="card"><div class="n" style="color:${color || "inherit"}">${n}</div><div class="l">${label}</div></div>`;
}

function render(data) {
  const latest = data.latest;
  if (!latest) {
    $("#sub").textContent = "No runs recorded yet.";
    return;
  }
  $("#sub").innerHTML =
    `Latest run <code>${latest.run_id}</code> · ${fmtDate(latest.timestamp_epoch)} · ` +
    `commit <code>${latest.commit.slice(0, 12)}</code> · server v${latest.server_version} · ` +
    `${data.runs.length} run(s) recorded`;

  const rate = (latest.passed / Math.max(1, latest.total - latest.skipped) * 100).toFixed(1);
  $("#cards").innerHTML = [
    card(latest.total, "cases"),
    card(latest.passed, "passed", "var(--pass)"),
    card(latest.failed, "failed", latest.failed ? "var(--fail)" : "inherit"),
    card(latest.errored, "errored", latest.errored ? "var(--err)" : "inherit"),
    card(latest.skipped, "skipped", "var(--skip)"),
    card(rate + "%", "pass rate"),
  ].join("");

  renderTrend(data.runs);

  $("#cats tbody").innerHTML = (data.categories || [])
    .map((c) => `<tr><td>${c.name}</td><td>${c.pass}</td><td>${c.fail}</td><td>${c.error}</td><td>${c.skip}</td></tr>`)
    .join("");

  $("#cases tbody").innerHTML = latest.cases
    .map((c) => {
      const metrics = Object.entries(c.metrics || {})
        .map(([k, v]) => `${k}=${v}`)
        .join(" ");
      const detail = [c.message, metrics].filter(Boolean).join(" · ");
      return `<tr><td>${pill(c.status)}</td><td><code>${c.id}</code></td><td>${c.category}</td>` +
        `<td class="muted">${c.spec}</td><td>${c.duration_ms}</td><td>${detail}</td></tr>`;
    })
    .join("");

  $("#runs tbody").innerHTML = data.runs
    .map((r) => {
      const pct = (r.pass_rate * 100).toFixed(1);
      return `<tr><td><code>${r.run_id}</code></td><td>${fmtDate(r.timestamp_epoch)}</td>` +
        `<td><code>${r.commit}</code></td><td>${r.server_version}</td>` +
        `<td>${r.passed}/${r.total}</td><td>${r.failed}</td>` +
        `<td><div class="bar" title="${pct}%"><span style="width:${pct}%"></span></div></td>` +
        `<td>${r.duration_ms}</td></tr>`;
    })
    .join("");
}

function renderTrend(runs) {
  if (!runs.length) return;
  const chron = [...runs].reverse();
  const blocks = "▁▂▃▄▅▆▇█";
  const spark = chron
    .map((r) => blocks[Math.min(blocks.length - 1, Math.round(r.pass_rate * (blocks.length - 1)))])
    .join("");
  const min = Math.min(...chron.map((r) => r.pass_rate * 100)).toFixed(0);
  const max = Math.max(...chron.map((r) => r.pass_rate * 100)).toFixed(0);
  $("#trend").innerHTML =
    `<div class="spark" style="font-size:1.6rem">${spark}</div>` +
    `<div class="muted" style="font-size:.8rem">${chron.length} runs · pass rate ${min}%–${max}%</div>`;
}

fetch("results.json", { cache: "no-store" })
  .then((r) => r.json())
  .then(render)
  .catch((e) => {
    $("#sub").textContent = "Could not load results.json: " + e;
  });
