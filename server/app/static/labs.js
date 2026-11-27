/* LabsVault: lab results per patient. Upload a Labcorp / Quest / Sonora Quest
   report, review what was read, save, and follow each test over time. */
(() => {
"use strict";
const { API, S, $, $$, esc, fmtDate, toast, modal, confirmBox, main, mobileHead, handleErr, go, wireDrop, I, initials } = window.SV;

const FLAG_TXT = { H: "High", L: "Low", HH: "Critical high", LL: "Critical low", A: "Abnormal", C: "Critical" };
const flagBadge = f => f ? `<span class="badge ${f === "A" ? "warn" : "err"}" title="${esc(FLAG_TXT[f] || f)}">${f === "H" || f === "HH" ? "▲" : f === "L" || f === "LL" ? "▼" : "!"} ${esc(FLAG_TXT[f] || f)}</span>` : "";
const fmtNum = v => v == null ? "" : String(+v.toFixed(4));
const refText = p => p.ref_text || (p.ref_low != null && p.ref_high != null ? `${fmtNum(p.ref_low)}–${fmtNum(p.ref_high)}` : p.ref_low != null ? `≥ ${fmtNum(p.ref_low)}` : p.ref_high != null ? `≤ ${fmtNum(p.ref_high)}` : "");
let INFO = null;
const info = async () => INFO || (INFO = await API.req("GET", "/api/labs/info"));

// ------------------------------------------------------------------ chart
// One series per test: a 2px line, 8px points, the reference interval as a
// shaded band. Out-of-range points get the status red AND an ▲/▼ glyph, so
// the flag never rests on color alone. Hover/focus snaps to the nearest date.
function chartSvg(points, { w = 640, h = 240, spark = false } = {}) {
  const pts = points.filter(p => p.value_num != null && p.date);
  if (!pts.length) return "";
  const t = pts.map(p => new Date(p.date + "T12:00:00").getTime());
  const last = [...pts].reverse().find(p => p.ref_low != null || p.ref_high != null) || pts[pts.length - 1];
  const lo = last.ref_low, hi = last.ref_high;
  let ymin = Math.min(...pts.map(p => p.value_num)), ymax = Math.max(...pts.map(p => p.value_num));
  if (lo != null) ymin = Math.min(ymin, lo); if (hi != null) ymax = Math.max(ymax, hi);
  const pad = (ymax - ymin) * 0.12 || Math.abs(ymax) * 0.1 || 1;
  ymin -= pad; ymax += pad;
  if (ymin < 0 && Math.min(...pts.map(p => p.value_num)) >= 0) ymin = Math.max(ymin, 0);
  const m = spark ? { l: 2, r: 2, t: 4, b: 4 } : { l: 48, r: 16, t: 14, b: 30 };
  let t0 = Math.min(...t), t1 = Math.max(...t);
  if (t0 === t1) { t0 -= 864e5 * 30; t1 += 864e5 * 30; }
  const X = v => m.l + (v - t0) / (t1 - t0) * (w - m.l - m.r);
  const Y = v => m.t + (1 - (v - ymin) / (ymax - ymin)) * (h - m.t - m.b);
  const band = (lo != null || hi != null) ? `<rect class="lband" x="${m.l}" width="${w - m.l - m.r}" y="${Y(hi != null ? hi : ymax)}" height="${Math.max(0, Y(lo != null ? lo : ymin) - Y(hi != null ? hi : ymax))}"/>` : "";
  const path = pts.map((p, i) => `${i ? "L" : "M"}${X(t[i]).toFixed(1)},${Y(p.value_num).toFixed(1)}`).join("");
  // Direction of an out-of-range point: the printed flag first, else the band.
  const dir = p => ["H", "HH"].includes(p.flag) ? 1 : ["L", "LL"].includes(p.flag) ? -1 : hi != null && p.value_num > hi ? 1 : lo != null && p.value_num < lo ? -1 : 0;
  const out = p => dir(p) !== 0;
  if (spark) return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">${band}<path class="lline" d="${path}" vector-effect="non-scaling-stroke"/>${pts.length === 1 ? `<circle class="lpt" cx="${X(t[0])}" cy="${Y(pts[0].value_num)}" r="3"/>` : ""}</svg>`;
  const ticks = [];
  for (let i = 0; i <= 4; i++) ticks.push(ymin + (ymax - ymin) * i / 4);
  const nice = v => Math.abs(ymax - ymin) < 5 ? v.toFixed(2).replace(/\.?0+$/, "") : Math.round(v);
  // Date labels: first and last always, others only where they don't collide.
  const xt = [];
  pts.forEach((p, i) => { const x = X(t[i]); if (i === 0 || i === pts.length - 1 || (x - X(xt[xt.length - 1][0]) > 110 && X(t[pts.length - 1]) - x > 110)) xt.push([t[i], p.date]); });
  if (xt.length > 1 && X(xt[xt.length - 1][0]) - X(xt[xt.length - 2][0]) < 110 && xt.length > 2) xt.splice(xt.length - 2, 1);
  return `<svg class="lchart" viewBox="0 0 ${w} ${h}" role="img" aria-label="Values over time; see the table below">
    ${ticks.map(v => `<line class="lgl" x1="${m.l}" x2="${w - m.r}" y1="${Y(v)}" y2="${Y(v)}"/><text class="lax" x="${m.l - 8}" y="${Y(v) + 4}" text-anchor="end">${nice(v)}</text>`).join("")}
    ${band}
    ${hi != null ? `<text class="lbandlbl" x="${w - m.r - 4}" y="${Y(hi) - 4}" text-anchor="end">High ${fmtNum(hi)}</text>` : ""}
    ${lo != null ? `<text class="lbandlbl" x="${w - m.r - 4}" y="${Y(lo) + 12 > h - m.b - 2 ? Y(lo) - 4 : Y(lo) + 12}" text-anchor="end">Low ${fmtNum(lo)}</text>` : ""}
    ${xt.map(([v, d], i) => `<text class="lax" x="${X(v)}" y="${h - 8}" text-anchor="${xt.length > 1 && i === 0 ? "start" : xt.length > 1 && i === xt.length - 1 ? "end" : "middle"}">${esc(fmtDate(d))}</text>`).join("")}
    <path class="lline" d="${path}"/>
    <line class="lcross" y1="${m.t}" y2="${h - m.b}" x1="-10" x2="-10"/>
    ${pts.map((p, i) => `<g class="lp ${out(p) ? "out" : ""} ${p.source === "previous" ? "prev" : ""}" data-i="${i}" tabindex="0" aria-label="${esc(fmtDate(p.date))}: ${esc(p.value)} ${esc(p.unit || "")}">
      <circle class="lhit" cx="${X(t[i])}" cy="${Y(p.value_num)}" r="14"/><circle class="lpt" cx="${X(t[i])}" cy="${Y(p.value_num)}" r="4.5"/>
      ${out(p) ? `<text class="lglyph" x="${X(t[i])}" y="${Y(p.value_num) + (dir(p) > 0 ? -10 : 18)}" text-anchor="middle">${dir(p) > 0 ? "▲" : "▼"}</text>` : ""}</g>`).join("")}
  </svg>`;
}

function wireChart(box, points) {
  const svg = $("svg.lchart", box); if (!svg) return;
  const pts = points.filter(p => p.value_num != null && p.date);
  const tip = document.createElement("div"); tip.className = "ltip"; box.appendChild(tip);
  const cross = $(".lcross", svg);
  const show = i => {
    const g = $(`.lp[data-i="${i}"]`, svg), c = $(".lpt", g), p = pts[i];
    const x = +c.getAttribute("cx");
    cross.setAttribute("x1", x); cross.setAttribute("x2", x); cross.classList.add("on");
    tip.innerHTML = "";
    const v = document.createElement("b"); v.textContent = `${p.value} ${p.unit || ""}`;
    const d = document.createElement("div"); d.className = "small muted"; d.textContent = [fmtDate(p.date), p.lab_name, p.source === "previous" ? "from a later report" : ""].filter(Boolean).join(" · ");
    tip.append(v, d);
    if (p.flag) { const f = document.createElement("div"); f.className = "small"; f.textContent = FLAG_TXT[p.flag] || p.flag; tip.appendChild(f); }
    const r = svg.getBoundingClientRect(), k = r.width / svg.viewBox.baseVal.width;
    tip.style.left = Math.min(r.width - 150, Math.max(0, x * k - 60)) + "px";
    tip.style.top = Math.max(0, +c.getAttribute("cy") * k - 70) + "px";
    tip.classList.add("on");
    $$(".lp", svg).forEach(n => n.classList.toggle("hl", n === g));
  };
  const hide = () => { tip.classList.remove("on"); cross.classList.remove("on"); cross.setAttribute("x1", -10); cross.setAttribute("x2", -10); $$(".lp", svg).forEach(n => n.classList.remove("hl")); };
  svg.addEventListener("pointermove", e => {
    const r = svg.getBoundingClientRect(), x = (e.clientX - r.left) / r.width * svg.viewBox.baseVal.width;
    let best = 0, bd = Infinity;
    $$(".lpt", svg).forEach((c, i) => { const d = Math.abs(+c.getAttribute("cx") - x); if (d < bd) { bd = d; best = i; } });
    show(best);
  });
  svg.addEventListener("pointerleave", hide);
  $$(".lp", svg).forEach(g => { g.addEventListener("focus", () => show(+g.dataset.i)); g.addEventListener("blur", hide); });
}

// ------------------------------------------------------------------ views
async function viewLabs(pid) {
  if (!pid) return pickPatient();
  const [p, an, reports] = await Promise.all([API.req("GET", `/api/patients/${pid}`), API.req("GET", `/api/patients/${pid}/labs/analytes`), API.req("GET", `/api/patients/${pid}/labs/reports`)]);
  const m = main();
  const drafts = reports.filter(r => r.status === "draft");
  const groups = {};
  an.forEach(a => (groups[a.panel] = groups[a.panel] || []).push(a));
  const flagged = an.filter(a => a.latest.flag);
  m.innerHTML = `${mobileHead()}<div class="crumbs"><a href="#/patients" data-go="patients">Patients</a><span>/</span><a href="#/patient/${esc(p.id)}" data-go="patient/${esc(p.id)}">${esc(p.name)}</a><span>/</span><span>Labs</span></div>
  <div class="top"><div><h1>Lab results</h1><p class="sub">${esc(p.name)} · ${an.length} ${an.length === 1 ? "test" : "tests"} tracked · ${reports.length - drafts.length} ${reports.length - drafts.length === 1 ? "report" : "reports"}</p></div>
    <div class="row">${an.length ? `<a class="btn" href="/api/patients/${esc(p.id)}/labs/export.csv" download>Export CSV</a>` : ""}<button class="btn" id="manual">${I.plus} Enter by hand</button><button class="btn primary" id="lup">${I.upload} Upload lab report</button></div></div>
  <div class="drop" id="ldrop">${I.flask}<div><b>Drop a lab report PDF here</b><div class="small muted">Labcorp, Quest and Sonora Quest reports are read automatically${S.labsOcr === false ? "" : ", scans and photos too"}. You check every value before it is saved. Nothing leaves this server.</div></div>
    <div class="row" style="justify-content:center"><label tabindex="0" role="button" class="btn sm">Choose PDF<input type="file" id="lfi" hidden accept="application/pdf,.pdf,image/*"></label>
    <label tabindex="0" role="button" class="btn sm">${I.camera} Take photo<input type="file" id="lcam" accept="image/*" capture="environment" hidden></label></div></div>
  <div id="lprog"></div>
  ${drafts.length ? `<div class="note warnnote">${I.warn}<div><b>${drafts.length} ${drafts.length === 1 ? "report is" : "reports are"} waiting for your review.</b> Values are only graphed after you check and save them.
    <div class="row" style="margin-top:8px">${drafts.map(d => `<button class="btn sm" data-review="${esc(d.id)}">Review ${esc(d.lab_name || d.filename || "report")}${d.collected ? " · " + esc(fmtDate(d.collected)) : ""}</button>`).join("")}</div></div></div>` : ""}
  ${flagged.length ? `<div class="section-h"><h2>Outside the reference range (latest)</h2></div><div class="lflags">${flagged.map(a => `<button class="card lflag" data-an="${esc(a.key)}"><span>${esc(a.name)}</span><b>${esc(a.latest.value)} <small>${esc(a.latest.unit || "")}</small></b>${flagBadge(a.latest.flag)}</button>`).join("")}</div>` : ""}
  ${an.length ? Object.entries(groups).map(([g, list]) => `<div class="section-h"><h2>${esc(g)}</h2></div><div class="lgrid">${list.map(a => `<button class="card lcard" data-an="${esc(a.key)}">
      <div class="lc-h"><span class="lc-n">${esc(a.name)}</span>${flagBadge(a.latest.flag)}</div>
      <div class="lc-v"><b>${esc(a.latest.value)}</b> <span class="muted small">${esc(a.latest.unit || "")}</span></div>
      ${chartSvg(a.spark.map(([date, value_num]) => ({ date, value_num, ref_low: a.latest.ref_low, ref_high: a.latest.ref_high })), { w: 200, h: 44, spark: true })}
      <div class="small muted">${esc(fmtDate(a.latest.date))} · ${a.count} ${a.count === 1 ? "result" : "results"}${refText(a.latest) ? " · ref " + esc(refText(a.latest)) : ""}</div></button>`).join("")}</div>`).join("")
    : `<div class="card empty">${I.flask}<h2>No lab results yet</h2><p>Upload a lab report PDF from Labcorp, Quest or Sonora Quest, or type results in by hand. Each test gets a graph over time with its reference range.</p></div>`}
  ${reports.length - drafts.length ? `<div class="section-h"><h2>Reports</h2></div><div class="card scroll"><table class="stk"><thead><tr><th>Collected</th><th>Lab</th><th>Results</th><th></th></tr></thead><tbody>
    ${reports.filter(r => r.status !== "draft").map(r => `<tr><td data-l="Collected">${esc(fmtDate(r.collected))}</td><td data-l="Lab">${esc(r.lab_name || "Lab")}${r.ordering_provider ? `<div class="small muted">${esc(r.ordering_provider)}</div>` : ""}</td>
      <td data-l="Results">${r.result_count}${r.flagged_count ? ` <span class="badge err">${r.flagged_count} flagged</span>` : ""}</td>
      <td class="num">${r.file_id ? `<a class="btn sm ghost" href="${esc(API.fileUrl(r.file_id))}" target="_blank" rel="noopener">PDF</a>` : ""}<button class="btn sm ghost" data-review="${esc(r.id)}">Edit</button></td></tr>`).join("")}</tbody></table></div>` : ""}`;
  const refresh = () => viewLabs(pid).catch(handleErr);
  const up = files => uploadLab(pid, files[0], refresh);
  wireDrop($("#ldrop"), up);
  $("#lup").onclick = () => $("#lfi").click();
  $("#lfi").onchange = e => e.target.files[0] && up([...e.target.files]);
  $("#lcam").onchange = e => e.target.files[0] && up([...e.target.files]);
  $("#manual").onclick = async () => { try { const r = await API.req("POST", `/api/patients/${pid}/labs/reports`, { lab: "other" }); review(r, p, refresh); } catch (e) { handleErr(e); } };
  $$("[data-review]").forEach(b => b.onclick = async () => { try { review(await API.req("GET", `/api/labs/reports/${b.dataset.review}`), p, refresh); } catch (e) { handleErr(e); } });
  $$("[data-an]").forEach(b => b.onclick = () => analyteModal(pid, b.dataset.an));
  info().then(i => { S.labsOcr = i.ocr; }).catch(() => {});
}

async function pickPatient() {
  const list = await API.req("GET", "/api/patients");
  if (list.length === 1) return go("labs", list[0].id);
  main().innerHTML = `${mobileHead()}<div class="top"><div><h1>Lab results</h1><p class="sub">Choose whose results to open.</p></div></div>
  <div class="plist">${list.length ? list.map(p => `<a class="card pcard" href="#/labs/${esc(p.id)}" data-go="labs/${esc(p.id)}"><div class="avatar">${esc(initials(p.name))}</div><div><h3>${esc(p.name)}</h3><div class="meta">${p.date_of_birth ? `<span>${esc(fmtDate(p.date_of_birth))}</span>` : ""}</div></div></a>`).join("")
    : `<div class="card empty" style="grid-column:1/-1">${I.users}<h2>Add a patient first</h2><p>Lab results belong to a patient record.</p><a class="btn primary" href="#/patients" data-go="patients">Go to patients</a></div>`}</div>`;
}

async function uploadLab(pid, file, done) {
  if (!file) return;
  const box = $("#lprog");
  box.innerHTML = `<div class="card qitem"><span class="spin"></span><div><b>${esc(file.name)}</b><div class="small muted" id="lpt">Uploading…</div></div></div>`;
  const fd = new FormData(); fd.append("file", file, file.name);
  try {
    const r = await API.upload(`/api/patients/${pid}/labs/upload`, fd, f => { const t = $("#lpt"); if (t) t.textContent = f < 1 ? `Uploading ${Math.round(f * 100)}%` : "Reading the report…"; });
    box.innerHTML = "";
    if (r.duplicate) toast("This report was uploaded before");
    const p = await API.req("GET", `/api/patients/${pid}`);
    review(r, p, done);
  } catch (e) { box.innerHTML = ""; handleErr(e); }
}

// ------------------------------------------------------------------ review
async function review(rep, patient, done) {
  const cat = (await info()).catalog;
  const opts = sel => `<option value="">Not in the list (keep the name)</option>${cat.map(a => `<option value="${esc(a.key)}" ${a.key === sel ? "selected" : ""}>${esc(a.name)} · ${esc(a.panel)}</option>`).join("")}`;
  let rows = (rep.rows || []).map(r => ({ ...r, include: true }));
  const saved = rep.status === "saved";
  const body = `
    ${rep.duplicate ? `<div class="note">${I.warn}<div>This file was uploaded before. You are looking at that report.</div></div>` : ""}
    ${(rep.warnings || []).length ? `<div class="note warnnote">${I.warn}<div>${rep.warnings.map(w => `<div>${esc(w)}</div>`).join("")}</div></div>` : ""}
    <div class="lrv-head">
      <label>Lab<select id="r_lab"><option value="labcorp">Labcorp</option><option value="sonora_quest">Sonora Quest Laboratories</option><option value="quest">Quest Diagnostics</option><option value="other">Other</option></select></label>
      <label>Collected<input type="date" id="r_col" value="${esc(rep.collected || "")}" required></label>
      <label>Reported<input type="date" id="r_rep" value="${esc(rep.reported || "")}"></label>
      <label>Ordering provider<input id="r_prov" value="${esc(rep.ordering_provider || "")}"></label>
    </div>
    ${rep.parsed_patient && rep.parsed_patient.patient_name ? `<p class="small muted">Report is for <b>${esc(rep.parsed_patient.patient_name)}</b>${rep.parsed_patient.dob ? `, born ${esc(fmtDate(rep.parsed_patient.dob))}` : ""}. Saving to <b>${esc(patient.name)}</b>.</p>` : ""}
    <div class="row" style="justify-content:space-between;margin:12px 0 6px"><span class="small muted">${rep.method === "ocr" ? "Read with OCR: check every value. " : ""}Rows marked <span class="badge warn">check</span> were hard to read.${rep.file_id ? ` <a href="${esc(API.fileUrl(rep.file_id))}" target="_blank" rel="noopener">Open the PDF</a> to compare.` : ""}</span>
      <button class="btn sm" id="r_add">${I.plus} Add a result</button></div>
    <div class="scroll"><table class="lrv"><thead><tr><th><span class="sr">Keep</span></th><th>Test</th><th>Result</th><th>Unit</th><th>Low</th><th>High</th><th>Flag</th><th>Matched to</th></tr></thead><tbody id="r_rows"></tbody></table></div>
    ${rows.some(r => r.prev_value) ? `<label class="check small" style="margin-top:10px"><input type="checkbox" id="r_prev" checked> Also keep the previous results the report lists (graphs get their earlier dates)</label>` : ""}
    <p class="small lerr" id="r_err" role="alert"></p>`;
  const mm = modal(saved ? "Edit lab report" : "Review lab results", body, { wide: true, footer: `<button class="btn danger" id="r_del">${saved ? "Delete report" : "Discard"}</button><span style="flex:1"></span><button class="btn" data-close>${saved ? "Cancel" : "Finish later"}</button><button class="btn primary" id="r_save">Save ${rows.length ? rows.length + " results" : "results"}</button>` });
  const el = mm.el;
  $("#r_lab", el).value = rep.lab || "other";
  const flagSel = f => `<select data-k="flag" aria-label="Flag"><option value=""></option>${Object.entries(FLAG_TXT).map(([k, v]) => `<option value="${k}" ${k === f ? "selected" : ""}>${esc(v)}</option>`).join("")}</select>`;
  const draw = () => {
    $("#r_rows", el).innerHTML = rows.map((r, i) => `<tr data-i="${i}" class="${r.include ? "" : "off"} ${r.confidence === "low" ? "low" : ""}">
      <td><input type="checkbox" data-k="include" ${r.include ? "checked" : ""} aria-label="Keep this result"></td>
      <td><input data-k="name" value="${esc(r.name)}" aria-label="Test name">${r.panel ? `<div class="small muted">${esc(r.panel)}</div>` : ""}${r.confidence === "low" ? `<span class="badge warn">check</span>` : ""}</td>
      <td><input data-k="value" value="${esc(r.value)}" class="lnum" aria-label="Result">${r.prev_value ? `<div class="small muted">prev ${esc(r.prev_value)} · ${esc(fmtDate(r.prev_date))}</div>` : ""}</td>
      <td><input data-k="unit" value="${esc(r.unit || "")}" class="lunit" aria-label="Unit"></td>
      <td><input data-k="ref_low" value="${esc(r.ref_low ?? "")}" class="lnum" inputmode="decimal" aria-label="Range low"></td>
      <td><input data-k="ref_high" value="${esc(r.ref_high ?? "")}" class="lnum" inputmode="decimal" aria-label="Range high">${r.ref_text && r.ref_low == null && r.ref_high == null ? `<div class="small muted">${esc(r.ref_text)}</div>` : ""}</td>
      <td>${flagSel(r.flag)}</td>
      <td><select data-k="analyte" aria-label="Matched test">${opts(r.analyte && !r.analyte.startsWith("x_") ? r.analyte : "")}</select></td></tr>`).join("") || `<tr><td colspan="8" class="muted">No results yet. Use “Add a result”.</td></tr>`;
    $("#r_save", el).textContent = `Save ${rows.filter(r => r.include).length} results`;
  };
  draw();
  $("#r_rows", el).addEventListener("input", e => {
    const tr = e.target.closest("tr[data-i]"); if (!tr) return;
    const r = rows[+tr.dataset.i], k = e.target.dataset.k;
    if (k === "include") { r.include = e.target.checked; tr.classList.toggle("off", !r.include); $("#r_save", el).textContent = `Save ${rows.filter(r => r.include).length} results`; }
    else if (k === "analyte") r.analyte = e.target.value || null;
    else r[k] = e.target.value;
  });
  $("#r_add", el).onclick = () => { rows.push({ name: "", value: "", include: true, source: "manual", confidence: "high" }); draw(); const ins = $$("#r_rows input[data-k=name]", el); ins[ins.length - 1].focus(); };
  const payload = () => ({
    lab: $("#r_lab", el).value, collected: $("#r_col", el).value || null, reported: $("#r_rep", el).value || null, ordering_provider: $("#r_prov", el).value,
    import_previous: $("#r_prev", el) ? $("#r_prev", el).checked : true,
    rows: rows.filter(r => r.include && (r.name || r.value)).map(r => ({ ...r, analyte: r.analyte || null, ref_low: r.ref_low === "" ? null : r.ref_low, ref_high: r.ref_high === "" ? null : r.ref_high, flag: r.flag || null })),
  });
  $("#r_save", el).onclick = async () => {
    const b = $("#r_save", el); b.disabled = true;
    try { await API.req("PUT", `/api/labs/reports/${rep.id}`, { ...payload(), save: true }); mm.close(); toast("Lab results saved"); done(); }
    catch (e) { $("#r_err", el).textContent = e.message; b.disabled = false; }
  };
  // "Finish later" keeps the edits so far in the draft.
  if (!saved) el.addEventListener("click", async e => {
    if (!e.target.closest("[data-close]") || e.target.closest("#r_save")) return;
    try { await API.req("PUT", `/api/labs/reports/${rep.id}`, payload()); } catch {}
    done();
  });
  $("#r_del", el).onclick = async () => {
    if (!await confirmBox(saved ? "Delete lab report" : "Discard this report", `${saved ? "Its results are removed from the graphs. " : ""}The uploaded PDF is deleted too.`, saved ? "Delete" : "Discard")) return;
    try { await API.req("DELETE", `/api/labs/reports/${rep.id}`); mm.close(); toast(saved ? "Report deleted" : "Discarded"); done(); } catch (e) { handleErr(e); }
  };
}

// ------------------------------------------------------------------ one test over time
async function analyteModal(pid, key) {
  let s;
  try { s = await API.req("GET", `/api/patients/${pid}/labs/analytes/${encodeURIComponent(key)}`); } catch (e) { return handleErr(e); }
  const unit = s.points[s.points.length - 1].unit || "";
  const same = s.points.filter(p => (p.unit || "") === unit);
  const others = s.points.length - same.length;
  const mm = modal(s.name, `
    <div class="row small muted" style="margin-bottom:8px;gap:14px">${s.loinc ? `<span>LOINC ${esc(s.loinc)}</span>` : ""}<span>${esc(unit)}</span>${refText(same[same.length - 1]) ? `<span>Reference ${esc(refText(same[same.length - 1]))}</span>` : ""}</div>
    ${others ? `<div class="note">${I.warn}<div>${others} older ${others === 1 ? "result uses" : "results use"} a different unit and ${others === 1 ? "is" : "are"} listed below but not graphed.</div></div>` : ""}
    <div class="lchartbox">${same.filter(p => p.value_num != null).length ? chartSvg(same, { w: Math.round(Math.max(340, Math.min(900, innerWidth - 80))), h: innerWidth < 600 ? 230 : 300 }) : `<p class="muted">These results are not numbers, so there is nothing to graph.</p>`}</div>
    <p class="small muted" style="margin:6px 0 14px">Shaded band: the lab's reference interval from the latest result. Points outside it are marked ▲ or ▼.</p>
    <div class="scroll"><table class="stk"><thead><tr><th>Date</th><th>Result</th><th>Reference</th><th>Lab</th></tr></thead><tbody>
    ${s.points.slice().reverse().map(p => `<tr><td data-l="Date">${esc(fmtDate(p.date))}${p.source === "previous" ? `<div class="small muted">from a later report</div>` : ""}</td><td data-l="Result"><b>${esc(p.value)}</b> ${esc(p.unit || "")} ${flagBadge(p.flag)}</td><td data-l="Reference">${esc(refText(p))}</td><td data-l="Lab">${esc(p.lab_name || "")}</td></tr>`).join("")}
    </tbody></table></div>`, { wide: true });
  wireChart($(".lchartbox", mm.el), same);
}

window.SV_VIEWS = { ...(window.SV_VIEWS || {}), labs: viewLabs };
if (S.status && S.route && S.route.name === "labs") render();
function render() { window.SV.render(); }
})();
