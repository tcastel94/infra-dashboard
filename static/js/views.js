/* InfraDash — rendu des vues */
"use strict";

const UI = { flowMode: "topo", machHost: "homelab", machRange: "24h", ctHost: "all", ctSort: ["cpu", -1], plHost: "all", plCat: "all",
  inLevel: "all", jrHost: "all", lastFull: 0, lastEvT: 0 };
let OV_TOPO = null, FLOW_TOPO = null, GALAXY = null, HARBOR = null, WORLD = null;
const setHTML = (el, html) => { if (el && el._h !== html) { el.innerHTML = html; el._h = html; } };
const L = () => S.live || {}, SL = () => S.slow || {}, D = () => S.derived || {};

function allContainers() {
  const out = [];
  (L().nas_containers || []).forEach((c) => out.push({ ...c, host: "nas" }));
  (L().homelab_containers || []).forEach((c) => out.push({ ...c, host: "homelab", status: "Up", health: "" }));
  const cl = L().clawhost || {};
  if (cl.metrics && cl.metrics.containers) cl.metrics.containers.forEach((c) => out.push({ ...c, host: "clawhost", state: "running", cat: "apps" }));
  else ((SL().nas_backups || {}).claw_inventory || "").split("\n# conteneurs")[1]?.split("\n").forEach((l) => {
    const p = l.split("\t"); if (p.length >= 3) out.push({ name: p[0], image: p[1], status: p[2] + " (inventaire)", state: /^Up/.test(p[2]) ? "running" : "exited", host: "clawhost", cat: "apps", inventory: true });
  });
  return out;
}
function healthScore() {
  const ins = D().insights || [];
  const crit = ins.filter((i) => i.level === "crit").length, warn = ins.filter((i) => i.level === "warn").length;
  const g = (D().scores || {}).global;   // note globale du barème si disponible
  return { score: g ? Math.round(g.score) : Math.max(0, 100 - crit * 10 - warn * 3), grade: g && g.grade, crit, warn };
}
function jobsList() { return (D().jobs || {}).jobs || []; }

/* ===================================================================== VUE D'ENSEMBLE */
function hostCard(id) {
  const H = { homelab: ["server", "Homelab", "homelab-netnode · 192.168.2.4", "Réseau, DNS & supervision"],
    nas: ["nas", "NAS Unraid", "TCASTELNAS · 192.168.2.3", "Stockage, médias, applis"],
    clawhost: ["claw", "clawhost", "192.168.2.5 · port SSH 2211", "Agent OpenClaw, Netscan"] }[id];
  return `<div class="card host" id="hc-${id}"><div class="host-head"><div class="host-ico" style="${id === "nas" ? "color:var(--violet);border-color:rgba(191,90,242,.3);background:rgba(191,90,242,.12)" : id === "clawhost" ? "color:var(--pink);border-color:rgba(255,55,95,.3);background:rgba(255,55,95,.12)" : ""}">${icon(H[0])}</div>
    <div><b>${H[1]}</b><div class="meta">${H[2]}</div><div class="meta">${H[3]}</div></div><span class="st tag" data-f="st">…</span></div>
    <div class="rings" data-f="rings"></div><div class="hstats" data-f="stats"></div><canvas class="spark" data-f="spark"></canvas></div>`;
}
function renderHostCards() {
  const el = $("#ov-hosts");
  if (!el.children.length) el.innerHTML = hostCard("homelab") + hostCard("nas") + hostCard("clawhost");
  const lv = L();
  const upd = (id, m, extra) => {
    const card = $("#hc-" + id); if (!card) return;
    const st = card.querySelector('[data-f="st"]');
    const ringsEl = card.querySelector('[data-f="rings"]');
    if (extra.state) { st.className = "st tag " + extra.state[0]; st.textContent = extra.state[1]; }
    if (!ringsEl.children.length || ringsEl.dataset.k !== extra.ringKey) {
      ringsEl.innerHTML = extra.rings.map(([v, l, c]) => ring(v, l, c)).join(""); ringsEl.dataset.k = extra.ringKey;
    } else $$(".ring", ringsEl).forEach((r, i) => updateRing(r, extra.rings[i][0]));
    setHTML(card.querySelector('[data-f="stats"]'), extra.stats.map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join(""));
    sparkline(card.querySelector('[data-f="spark"]'), extra.spark, extra.sparkColor || "#64D2FF");
  };
  const h = lv.homelab || {};
  const rootPct = h.root_fs ? 100 * (1 - h.root_fs.free / h.root_fs.size) : null;
  upd("homelab", h, { state: h.cpu != null ? ["ok", "en ligne"] : ["mute", "…"], ringKey: "h",
    rings: [[h.cpu, "CPU"], [h.mem, "RAM"], [rootPct, "Disque"], [h.temps ? h.temps.cpu : null, "°C", "var(--pink)"]],
    stats: [["Charge", (h.load || []).map((x) => nf1.format(x)).join(" ")], ["Réseau", `↓${fmtRate(h.rx)}`], ["Conteneurs", (lv.homelab_containers || []).length],
      ["Uptime", fmtDur(h.uptime)], ["Envoi", `↑${fmtRate(h.tx)}`], ["DNS", lv.dns ? (lv.dns.ok ? lv.dns.ms + " ms" : "KO") : "–"]],
    spark: ((h.hist || {}).rx || []).map((p, i) => p[1] + (((h.hist || {}).tx || [])[i] || [0, 0])[1]) });
  const n = lv.nas || {};
  const disks = (SL().nas || {}).disks || {};
  let used = 0, size = 0; Object.values(disks).forEach((d) => { if (d.fsSize && d.type === "Data") { size += +d.fsSize; used += d.fsSize - d.fsFree; } });
  const arr = n.array || {};
  const parity = +arr.mdResyncPos > 0 ? (100 * arr.mdResyncPos) / (arr.mdResyncSize || arr.mdResync) : null;
  const gpu = (SL().nas || {}).gpu;
  upd("nas", n, { state: n.down ? ["crit", "injoignable"] : n.cpu != null ? (parity ? ["warn", `parité ${nf1.format(parity)} %`] : ["ok", "en ligne"]) : ["mute", "…"], ringKey: "n",
    rings: [[n.cpu, "CPU", "var(--violet)"], [n.mem, "RAM", "var(--violet)"], [size ? (100 * used) / size : null, "Array"], [n.iowait, "IOwait", "var(--amber)"]],
    stats: [["Charge", (n.load || []).map((x) => nf1.format(x)).join(" ")], ["Réseau", `↓${fmtRate(n.rx)}`], ["Conteneurs", `${(lv.nas_containers || []).filter((c) => c.state === "running").length}/${(lv.nas_containers || []).length}`],
      ["Disques R/W", `${fmtRate(n.dread)}`], ["Envoi", `↑${fmtRate(n.tx)}`], ["GPU", gpu ? `${nf0.format(gpu.util || 0)} % · ${nf0.format(gpu.temp || 0)}°` : "–"]],
    spark: ((n.hist || {}).cpu || []).map((p) => p[1]), sparkColor: "#BF5AF2" });
  const c = lv.clawhost || {};
  const pr = c.probes || [];
  const upN = pr.filter((p) => p.up).length;
  const m = c.metrics;
  upd("clawhost", c, { state: c.up ? (m ? ["ok", "en ligne"] : ["ok", "en ligne · sondes"]) : c.t ? ["crit", "injoignable"] : ["mute", "…"],
    ringKey: m ? "cm" : "cp",
    rings: m ? [[m.cpu, "CPU", "var(--pink)"], [m.mem, "RAM", "var(--pink)"]] : [[pr.length ? (100 * upN) / pr.length : null, "Sondes", "var(--pink)"],
      [(c.ping_hist || []).length ? (100 * c.ping_hist.filter((v) => v != null).length) / c.ping_hist.length : null, "Dispo", "var(--green)"]],
    stats: [["Ping", c.ping != null ? nf1.format(c.ping) + " ms" : "–"], ["Gateway", (pr.find((p) => p.port === 18789) || {}).up ? "OK" : "KO"],
      ["Netscan", (pr.find((p) => p.port === 3000) || {}).up ? "OK" : "KO"], ["SSH :2211", (pr.find((p) => p.port === 2211) || {}).up ? "ouvert" : "fermé"],
      ["Tailscale", ((L().tailscale || {}).peers || []).find((p) => p.host === "clawhost")?.online ? "en ligne" : "hors ligne"],
      ["Dernière sauv.", ago(((D().backups || {}).chains || []).find((x) => x.id === "clawhost")?.last_time)]],
    spark: (c.ping_hist || []).map((v) => v ?? 0), sparkColor: "#FF375F" });
}
function renderKpis() {
  const lv = L(), d = D(), hs = healthScore();
  const conts = allContainers().filter((c) => !c.inventory);
  const run = conts.filter((c) => c.state === "running").length;
  const up = ["homelab", "nas"].filter((h) => lv[h] && lv[h].cpu != null && !lv[h].down).length + (lv.clawhost && lv.clawhost.up ? 1 : 0);
  const topo = S.topology || { edges: [] };
  const total = topo.edges.filter((e) => e.kind === "uplink").reduce((a, e) => a + e.ab + e.ba, 0);
  const jobs = jobsList(); const runs24 = jobs.filter((j) => (j.per_day || 0) <= 30).reduce((a, j) => a + (j.runs24 || []).length, 0);
  const ch = (d.backups || {}).chains || [];
  const pub = (SL().public || {}).endpoints || [];
  const sp = SL().speedtest || {};
  const k = [
    ["Machines", `${up}<small>/ 3</small>`, "en ligne", "var(--green)"],
    ["Conteneurs", `${run}<small>/ ${conts.length}</small>`, "actifs sur 3 hôtes", "var(--cyan)"],
    ["Trafic LAN", fmtRate(total).replace(" ", "<small>") + "</small>", "liens des machines", "var(--blue)"],
    ["Tâches 24 h", `${runs24}`, `${jobs.filter((j) => j.enabled).length} planifiées`, "var(--violet)"],
    ["Sauvegardes", `${ch.filter((c) => c.status === "ok").length}<small>/ ${ch.length}</small>`, "chaînes à jour", ch.some((c) => c.status === "crit") ? "var(--red)" : "var(--green)"],
    ["Alertes", `${hs.crit}<small>crit.</small> ${hs.warn}<small>att.</small>`, `score santé ${hs.score}/100`, hs.crit ? "var(--red)" : "var(--amber)"],
    ["Domaines", `${pub.filter((p) => p.ok).length}<small>/ ${pub.length}</small>`, "*.jposyno.eu joignables", pub.some((p) => !p.ok) ? "var(--red)" : "var(--green)"],
    ["Internet", sp.download ? `${nf0.format(sp.download / 1e6)}<small>Mb/s</small>` : "–", sp.upload ? `↑ ${nf0.format(sp.upload / 1e6)} Mb/s · ${nf0.format(sp.ping || 0)} ms` : "speedtest", "var(--pink)"],
  ];
  setHTML($("#ov-kpis"), k.map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
}
function insightHTML(i) {
  const ic = i.level === "crit" ? "x" : i.level === "warn" ? "alert" : "info";
  return `<div class="ins ${i.level}"><div class="ii">${icon(ic)}</div><div><b>${esc(i.title)}</b><p>${esc(i.detail)}</p>
    ${i.action ? `<div class="act">${esc(i.action)}</div>` : ""}<div class="tags"><span class="tag">${esc(HOST_LABEL[i.host] || i.host)}</span>${i.tag ? `<span class="tag mute">${esc(i.tag)}</span>` : ""}</div></div></div>`;
}
function eventHTML(e, fresh) {
  return `<div class="ev ${fresh ? "new" : ""}"><time>${new Date(e.t * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}</time><span class="dot ${e.level === "crit" ? "crit" : e.level === "warn" ? "warn" : e.level === "ok" ? "ok" : ""}"></span>
    <div>${esc(e.title)} <span class="tag mute">${esc(HOST_LABEL[e.host] || e.host)}</span>${e.detail ? `<small>${esc(e.detail)}</small>` : ""}</div></div>`;
}
function renderOverview(first) {
  renderScoreStrip(); renderKpis(); renderHostCards();
  if (!OV_TOPO) OV_TOPO = new Topology($("#ov-topo"), { small: true, labels: false, onNode: (id) => { if (["homelab", "nas", "clawhost"].includes(id)) { UI.machHost = id; location.hash = "#machines"; } else location.hash = "#flows"; } });
  OV_TOPO.setData(S.topology);
  const ins = D().insights || [];
  setHTML($("#ov-insights"), ins.filter((i) => i.level !== "info").slice(0, 7).map(insightHTML).join("") || '<div class="empty">Rien à signaler 🎉</div>');
  if (first || Date.now() - (UI.clockT || 0) > 30000) {
    UI.clockT = Date.now();
    const nxt = cronClock($("#ov-clock"), jobsList());
    setHTML($("#ov-next"), nxt.slice(0, 9).map(([t, j]) => `<div class="nx"><time>${fmtTime(t)}</time><div>${esc(j.title)}<div class="cell-sub">${esc(HOST_LABEL[j.host])} · ${esc(j.human || "")}</div></div><span class="cd" data-cd="${t}">${fmtCountdown(t - Date.now() / 1000)}</span></div>`).join("") || '<div class="empty">Chargement…</div>');
  }
  const ev = (S.events || []).slice(-30).reverse();
  setHTML($("#ov-events"), ev.map((e) => eventHTML(e, e.t > UI.lastEvT && UI.lastEvT > 0)).join("") || '<div class="empty">Les changements détectés apparaîtront ici (conteneurs, sauvegardes, pairs…)</div>');
}

/* ===================================================================== FLUX */
function renderFlows(first) {
  const wrap = $("#flow-topo");
  if (!wrap.dataset.init) {
    wrap.innerHTML = '<div class="t-topo" style="position:absolute;inset:0"></div><div class="t-gal" style="position:absolute;inset:0;display:none"></div>';
    wrap.dataset.init = 1;
    FLOW_TOPO = new Topology($(".t-topo", wrap), { onNode: (id) => { if (id === "nas" || id === "homelab") setFlowMode(id); else if (["lan", "pc", "ha", "box", "mobile"].includes(id)) setFlowMode("lan"); else if (id === "clawhost") { UI.machHost = "clawhost"; location.hash = "#machines"; } } });
    GALAXY = new Galaxy($(".t-gal", wrap));
    segment($("#flow-mode"), (b) => setFlowMode(b.dataset.m));
    segment($("#flow-opts"), (b) => { FLOW_TOPO.opts[b.dataset.o] = b.classList.contains("on"); FLOW_TOPO.updateEdgeLabels(); });
  }
  const sub = location.hash.split("/")[1];
  if (first && sub && ["nas", "homelab", "topo", "lan"].includes(sub) && sub !== UI.flowMode) setFlowMode(sub);
  FLOW_TOPO.setData(S.topology);
  if (UI.flowMode !== "topo") GALAXY.setData(galaxyData(UI.flowMode), UI.flowMode);
  const edges = ((S.topology || {}).edges || []).slice().sort((a, b) => b.ab + b.ba - (a.ab + a.ba));
  const nodes = (S.topology || {}).nodes || {};
  const nm = (id) => (nodes[id] || {}).label || id;
  const tot = edges.reduce((a, e) => a + e.ab + e.ba, 0);
  $("#flow-total").textContent = `${edges.length} liens · ${fmtRate(tot)}`;
  setHTML($("#flow-list"), edges.map((e) => { const [c, p] = PROTO[e.proto] || PROTO.tcp;
    return `<div class="flow-row"><span class="sw" style="background:${c};color:${c}"></span><div class="nm">${esc(nm(e.from))} ⇄ ${esc(nm(e.to))}<small>${esc(p)} · ${esc(e.label)}${e.estimated ? " · estimé" : ""}</small></div>
      <div class="rt">${fmtRate(e.ab + e.ba)}<small>→ ${fmtRate(e.ab)} · ← ${fmtRate(e.ba)}</small></div></div>`; }).join(""));
  // graphe temps réel
  const h = L().homelab || {}, n = L().nas || {};
  const ser = (hist, k) => ((hist || {})[k] || []).map((p) => [p[0] * 1000, p[1]]);
  const c = chart($("#ch-net-live"));
  c && c.setOption(baseOpt({
    grid: { left: 54, right: 16, top: 30, bottom: 26 }, xAxis: TAX, yAxis: { type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: (v) => fmtBytes(v, 0) } },
    tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => fmtRate(v) },
    series: [lineSeries("Homelab ↓", ser(h.hist, "rx"), "#64D2FF"), lineSeries("Homelab ↑", ser(h.hist, "tx"), "#66D4CF", false),
      lineSeries("NAS ↓", ser(n.hist, "rx"), "#BF5AF2"), lineSeries("NAS ↑", ser(n.hist, "tx"), "#FF375F", false)],
  }), { notMerge: false, lazyUpdate: true });
  const lan = Object.fromEntries(((SL().lan || {}).devices || []).map((d) => [d.ip, d]));
  const cl = (S.topology || {}).clients || [];
  setHTML($("#flow-clients"), cl.length ? `<div class="tbl-wrap"><table><tr><th>Client</th><th>Services utilisés</th><th class="num">Débit estimé</th></tr>${cl.map((x) =>
    `<tr><td><b class="mono">${esc(x.ip)}</b><div class="cell-sub">${esc((lan[x.ip] || {}).name || (lan[x.ip] || {}).vendor || "")}</div></td><td>${Object.entries(x.services).map(([s, k]) => `<span class="tag">${esc(s.replace(/^binhex-/, ""))} ×${k}</span>`).join(" ")}</td><td class="num">${fmtRate(x.rx + x.tx)}</td></tr>`).join("")}</table></div>`
    : '<div class="empty">Aucun client LAN actif sur le NAS en ce moment</div>');
}
const LAN_FLAG = { nouveau: "jamais vu par NetScan", ip: "IP changée", "à identifier": "à identifier" };
function lanDevices() { return ((SL().lan_devices || {}).devices || []); }
function lanBad() { return new Set((((SL().netscan || {}).digest || {}).active || []).map((g) => g.mac)); }
function galaxyData(m) {
  if (m === "nas") return L().nas_containers;
  if (m === "homelab") return L().homelab_containers;
  const bad = lanBad(), cl = Object.fromEntries(((S.topology || {}).clients || []).map((x) => [x.ip, x]));
  return lanDevices().filter((d) => d.alive).map((d) => {
    const infra = !!d.infra, col = bad.has(d.mac) ? "#FF453A" : d.known ? "#30D158" : "#FF9F0A", t = cl[d.ip] || {};
    return { key: d.mac, name: d.mac, label: d.name, project: d.cat, state: "running", r: infra ? 13 : 9, col, showLabel: infra || (d.known && !/\.home$|^[0-9a-f-]{12,}/i.test(d.name)),
      cpu: 0, rx: t.rx || 0, tx: t.tx || 0,
      tip: `<b>${esc(d.name)}</b><div class="cell-sub">${esc(d.vendor || "")}</div><div class="sep"></div>
        <div class="row"><span>IP</span><b class="mono">${esc(d.ip || "")}</b></div><div class="row"><span>MAC</span><span class="mono" style="font-size:11px">${esc(d.mac)}</span></div>
        <div class="row"><span>Famille</span><span>${esc(d.cat)}</span></div>
        <div class="row"><span>Statut</span><span>${d.known ? "identifié" : "à identifier"}${d.flags.includes("nouveau") ? " · jamais vu par NetScan" : ""}</span></div>
        ${d.flags.includes("ip") ? `<div class="row"><span>NetScan</span><span>le voyait en ${esc(d.ns_ip)}</span></div>` : ""}
        ${(d.services || []).length ? `<div class="row"><span>Services</span><span>${esc(d.services.join(", "))}</span></div>` : ""}
        ${t.rx || t.tx ? `<div class="row"><span>Avec le NAS</span><b>${fmtRate((t.rx || 0) + (t.tx || 0))}</b></div>` : ""}` };
  });
}
function setFlowMode(m) {
  UI.flowMode = m;
  $$("#flow-mode button").forEach((b) => b.classList.toggle("on", b.dataset.m === m));
  $(".t-topo").style.display = m === "topo" ? "" : "none"; $(".t-gal").style.display = m === "topo" ? "none" : "";
  $("#flow-opts").style.display = m === "topo" ? "" : "none";
  $("#flow-hint").textContent = m === "topo" ? "Particules proportionnelles au débit réel (échelle log). Survolez un lien ou un nœud ; cliquez le NAS, le homelab ou les appareils du LAN pour plonger dedans."
    : m === "lan" ? "Appareils présents en ce moment (vus par le homelab, DNS du réseau), regroupés par famille ; noms et types issus de NetScan, rapprochés par adresse MAC. Vert = identifié, orange = à identifier, rouge = vulnérabilité confirmée. Particules = échanges avec le NAS."
    : "Bulle = conteneur (taille ∝ RAM, halo ∝ CPU, arc blanc = % CPU). Particules cyan = réception, roses = émission. Regroupés par projet compose.";
  if (m !== "topo") { GALAXY.resize(); GALAXY.setData(galaxyData(m), m); }
}

/* ===================================================================== MACHINES */
async function loadHist(host, range) {
  const keys = ["cpu", "mem", "rx", "tx", "load"].concat(host === "homelab" ? ["temp"] : []);
  const res = await Promise.all(keys.map((k) => history(k, host, range)));
  return Object.fromEntries(keys.map((k, i) => [k, res[i]]));
}
function seriesFrom(h, color, name) { return lineSeries(name, ((h && h.series && h.series[0]) || { values: [] }).values.map(([t, v]) => [t * 1000, v]), color); }
async function renderMachineHistory() {
  const host = UI.machHost, range = UI.machRange;
  if (host === "clawhost") return;
  const H = await loadHist(host, range);
  const col = host === "nas" ? "#BF5AF2" : "#64D2FF";
  const pctAx = { type: "value", min: 0, max: 100, ...AX, axisLabel: { ...AX.axisLabel, formatter: "{value} %" } };
  const tAx = { type: "time", ...AX, splitLine: { show: false } };
  const c1 = chart($("#mh-cpu")); c1 && c1.setOption(baseOpt({ xAxis: tAx, yAxis: pctAx, tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => fmtPct(v) },
    series: [seriesFrom(H.cpu, col, "CPU"), seriesFrom(H.mem, "#FF375F", "RAM")] }), true);
  const c2 = chart($("#mh-net")); c2 && c2.setOption(baseOpt({ xAxis: tAx, yAxis: { type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: (v) => fmtBytes(v, 0) } },
    tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => fmtRate(v) }, series: [seriesFrom(H.rx, "#64D2FF", "Réception"), seriesFrom(H.tx, "#A3D977", "Émission")] }), true);
  const c3 = chart($("#mh-load")); c3 && c3.setOption(baseOpt({ xAxis: tAx, yAxis: { type: "value", ...AX }, series: [seriesFrom(H.load, "#FF9F0A", "Charge 1 min")].concat(H.temp ? [Object.assign(seriesFrom(H.temp, "#FF453A", "Temp. CPU °C"), { yAxisIndex: 0 })] : []) }), true);
  const pts = ((H.cpu.series || [])[0] || { values: [] }).values.length;
  $("#mach-hint").textContent = host === "nas" && pts < 20 ? "Historique NAS : collecté par ce dashboard depuis son installation (VictoriaMetrics)." : host === "homelab" ? "Historique : node-exporter → VictoriaMetrics (rétention 12 mois)." : "";
}
function liveCharts(host) {
  const m = host === "nas" ? L().nas : host === "homelab" ? L().homelab : (L().clawhost || {}).metrics;
  if (!m || !m.hist) return;
  const s = (k) => (m.hist[k] || []).map((p) => [p[0] * 1000, p[1]]);
  const c = chart($("#ml-cpu"));
  c && c.setOption(baseOpt({ grid: { left: 40, right: 12, top: 30, bottom: 24 }, xAxis: TAX, yAxis: { type: "value", min: 0, max: 100, ...AX },
    tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => fmtPct(v) },
    series: [lineSeries("CPU", s("cpu"), "#64D2FF"), lineSeries("RAM", s("mem"), "#FF375F", false)] }));
  const c2 = chart($("#ml-io"));
  c2 && c2.setOption(baseOpt({ grid: { left: 54, right: 12, top: 30, bottom: 24 }, legend: { ...baseOpt().legend, type: "scroll" }, xAxis: TAX, yAxis: { type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: (v) => fmtBytes(v, 0) } },
    tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => fmtRate(v) },
    series: [lineSeries("Réseau ↓", s("rx"), "#64D2FF"), lineSeries("Réseau ↑", s("tx"), "#A3D977", false), lineSeries("Disque lecture", s("dread"), "#BF5AF2", false), lineSeries("Disque écriture", s("dwrite"), "#FF9F0A", false)] }));
}
function kv(items) { return `<div class="mini-kv">${items.map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join("")}</div>`; }
function ifaceTable(ifaces) {
  const rows = Object.entries(ifaces || {}).filter(([n, v]) => n !== "lo" && (v.rx_total > 0 || v.tx_total > 0)).sort((a, b) => b[1].rx + b[1].tx - (a[1].rx + a[1].tx)).slice(0, 14);
  return `<table><tr><th>Interface</th><th class="num">↓ débit</th><th class="num">↑ débit</th><th class="num">Total reçu</th><th class="num">Total émis</th><th class="num">Pertes</th></tr>${rows.map(([n, v]) =>
    `<tr><td class="mono">${esc(n)}</td><td class="num">${fmtRate(v.rx)}</td><td class="num">${fmtRate(v.tx)}</td><td class="num">${fmtBytes(v.rx_total)}</td><td class="num">${fmtBytes(v.tx_total)}</td><td class="num">${v.drop || 0}</td></tr>`).join("")}</table>`;
}
function renderMachines(first) {
  if (first && !$("#mach-host").dataset.init) {
    $("#mach-host").dataset.init = 1;
    segment($("#mach-host"), (b) => { UI.machHost = b.dataset.h; renderMachines(true); });
    segment($("#mach-range"), (b) => { UI.machRange = b.dataset.r; renderMachineHistory(); });
  }
  $$("#mach-host button").forEach((b) => b.classList.toggle("on", b.dataset.h === UI.machHost));
  $("#mach-range").style.display = UI.machHost === "clawhost" ? "none" : "";
  const host = UI.machHost, body = $("#mach-body");
  if (first || body.dataset.host !== host) {
    body.dataset.host = host; body._h = null;
    body.innerHTML = host === "clawhost" ? `<div class="grid g2"><div class="card" id="mc-head"></div><div class="card"><h2>Sondes de disponibilité <span class="r hint">toutes les 10 s</span></h2><div id="mc-probes"></div></div></div>
      <div class="grid g2 mt"><div class="card"><h2>Latence ping</h2><div class="chart short" id="mc-ping"></div></div><div class="card"><h2>Montages réseau de clawhost <span class="r hint">fstab, sauvegarde de la nuit</span></h2><div id="mc-mounts"></div></div></div>
      <div class="grid g2 mt"><div class="card"><h2>Dernier inventaire connu <span class="r hint">sauvegarde nocturne sur le NAS</span></h2><div id="mc-inv"></div></div><div class="card"><h2>Collecte détaillée</h2><div id="mc-howto"></div></div></div>`
      : `<div class="grid g2"><div class="card" id="mm-head"></div><div class="grid g2" style="gap:16px"><div class="card"><h2>CPU &amp; RAM <span class="r hint">live</span></h2><div class="chart short" id="ml-cpu"></div></div><div class="card"><h2>Réseau &amp; disques <span class="r hint">live</span></h2><div class="chart short" id="ml-io"></div></div></div></div>
      <div class="grid g3 mt"><div class="card"><h2>CPU &amp; RAM <span class="r hint">historique</span></h2><div class="chart" id="mh-cpu"></div></div><div class="card"><h2>Réseau <span class="r hint">historique</span></h2><div class="chart" id="mh-net"></div></div><div class="card"><h2>Charge${host === "homelab" ? " &amp; température" : ""} <span class="r hint">historique</span></h2><div class="chart" id="mh-load"></div></div></div>
      <div class="grid g2 mt"><div class="card"><h2>Interfaces réseau</h2><div class="tbl-wrap" id="mm-if"></div></div><div class="card" id="mm-extra"></div></div>
      ${host === "nas" ? '<div class="grid g3 mt"><div class="card" id="mm-gpu"></div><div class="card" id="mm-ups"></div><div class="card" id="mm-sensors"></div></div><div class="card mt" id="mm-notif"></div>' : '<div class="grid g2 mt"><div class="card" id="mm-mounts"></div><div class="card" id="mm-ports"></div></div>'}`;
    if (host !== "clawhost") renderMachineHistory();
  }
  if (host === "clawhost") return renderClawhost();
  const m = host === "nas" ? L().nas || {} : L().homelab || {};
  const sl = host === "nas" ? SL().nas || {} : SL().homelab || {};
  liveCharts(host);
  if (host === "homelab") {
    const apt = SL().homelab_apt || {};
    setHTML($("#mm-head"), `<h2>Homelab · homelab-netnode <span class="r tag ok">en ligne</span></h2>
      <div class="rings">${ring(m.cpu, "CPU")}${ring(m.mem, "RAM")}${ring(m.root_fs ? 100 * (1 - m.root_fs.free / m.root_fs.size) : 0, "Disque")}${ring(m.temps && m.temps.cpu, "°C", "var(--pink)")}</div>
      ${kv([["OS", "Debian 13"], ["Noyau", esc(sl.kernel || "–")], ["Uptime", fmtDur(m.uptime)], ["Charge", (m.load || []).map((x) => nf1.format(x)).join(" / ")],
        ["RAM", `${fmtBytes(m.mem_used)} / ${fmtBytes(m.mem_total)}`], ["Swap", fmtBytes(m.swap_used)], ["Mises à jour", apt.pending != null ? `${apt.pending} en attente` : "–"],
        ["Reboot requis", sl.reboot_required ? '<span style="color:var(--warn)">oui</span>' : "non"]])}
      <div class="hint mt">4 cœurs · 7,6 Go RAM · NVMe 220 Go. Porte le DNS du réseau (AdGuard → Unbound), la supervision (Uptime Kuma, VictoriaMetrics, Dozzle) et ce dashboard.</div>`);
    setHTML($("#mm-mounts"), `<h2>Systèmes de fichiers</h2><table><tr><th>Point de montage</th><th>Source</th><th>Type</th><th class="num">Utilisé</th></tr>${(sl.mounts || []).map((x) => { const p = x.size ? (100 * x.used) / x.size : 0;
      return `<tr><td class="mono">${esc(x.target)}</td><td class="mono cell-sub">${esc(x.source)}</td><td>${esc(x.fstype)}</td><td class="num"><div class="row-flex" style="justify-content:flex-end"><div class="bar ${pctClass(p)}" style="width:70px"><i style="width:${p}%"></i></div>${fmtBytes(x.used)} / ${fmtBytes(x.size)}</div></td></tr>`; }).join("")}</table>
      <div class="hint mt">La copie vers le NAS (//192.168.2.3/backups) est montée uniquement pendant la sauvegarde de 03:30 puis démontée.</div>`);
    const known = { 22: "SSH", 53: "DNS AdGuard", 3001: "Uptime Kuma", 3002: "Grafana", 7070: "InfraDash", 8080: "Dozzle", 8081: "cAdvisor", 8085: "AdGuard (UI)", 8086: "Speedtest Tracker", 8428: "VictoriaMetrics", 9100: "node-exporter" };
    const ports = {}; (sl.listen || []).forEach((p) => { (ports[p.port] = ports[p.port] || []).push(p.addr); });
    setHTML($("#mm-ports"), `<h2>Ports à l'écoute</h2><table><tr><th>Port</th><th>Service</th><th>Adresse</th><th>Exposition</th></tr>${Object.entries(ports).sort((a, b) => a[0] - b[0]).map(([p, a]) => {
      const local = a.every((x) => x.startsWith("127.") || x === "::1"); const ts = a.every((x) => x.startsWith("100.") || x.startsWith("fd7a"));
      return `<tr><td class="mono">${p}</td><td>${esc(known[p] || "")}</td><td class="mono cell-sub">${esc([...new Set(a)].join(", "))}</td><td>${local ? '<span class="tag ok">local</span>' : ts ? '<span class="tag info">Tailscale</span>' : '<span class="tag warn">LAN</span>'}</td></tr>`; }).join("")}</table>`);
    setHTML($("#mm-extra"), `<h2>Capteurs</h2><table><tr><th>Capteur</th><th class="num">°C</th></tr>${Object.entries((m.temps || {}).sensors || {}).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="num">${nf1.format(v)}</td></tr>`).join("")}</table>
      <div class="sep"></div><h2>Conteneurs du homelab</h2>${(L().homelab_containers || []).map((c) => `<span class="tag" style="margin:2px">${esc(c.name)} · ${fmtPct(c.cpu)}</span>`).join("")}`);
  } else {
    const ups = sl.ups || {}, gpu = sl.gpu, arr = m.array || {};
    setHTML($("#mm-head"), `<h2>NAS · TCASTELNAS <span class="r tag ${m.down ? "crit" : "ok"}">${m.down ? "injoignable" : "en ligne"}</span></h2>
      <div class="rings">${ring(m.cpu, "CPU", "var(--violet)")}${ring(m.mem, "RAM", "var(--violet)")}${ring(m.iowait, "IOwait", "var(--amber)")}${ring(gpu ? gpu.util : 0, "GPU", "var(--green)")}</div>
      ${kv([["OS", "Unraid " + esc(arr.version || "")], ["CPU", esc((sl.cpu_model || "").replace("Intel(R) Core(TM) ", "").replace(" CPU", ""))], ["Uptime", fmtDur(m.uptime)], ["Charge", (m.load || []).map((x) => nf1.format(x)).join(" / ")],
        ["RAM utilisée", `${fmtBytes(m.mem_used)} / ${fmtBytes(m.mem_total)}`], ["Cache page", fmtBytes(m.mem_cache)], ["Array", esc(arr.mdState || "–")], ["VMs", (sl.vms || []).map((v) => `${esc(v.name)} (${esc(v.state)})`).join(", ") || "–"]])}`);
    setHTML($("#mm-gpu"), gpu ? `<h2>GPU · ${esc(gpu.name)}</h2>${kv([["Utilisation", fmtPct(gpu.util)], ["Température", nf0.format(gpu.temp) + " °C"], ["VRAM", `${nf0.format(gpu.mem_used)} / ${nf0.format(gpu.mem_total)} Mo`], ["Puissance", nf1.format(gpu.power) + " W"], ["Ventilateur", gpu.fan != null ? gpu.fan + " %" : "–"], ["Processus", (gpu.procs || []).map(esc).join(", ") || "aucun"]])}<div class="hint mt">Utilisé par Jellyfin (transcodage NVENC) et Ollama.</div>` : "<h2>GPU</h2><div class='empty'>–</div>");
    setHTML($("#mm-ups"), `<h2>Onduleur · ${esc(ups.MODEL || "–")}</h2>${kv([["État", esc(ups.STATUS || "–")], ["Batterie", esc(ups.BCHARGE || "–")], ["Autonomie", esc(ups.TIMELEFT || "–")], ["Charge", esc(ups.LOADPCT || "–")], ["Tension", esc(ups.LINEV || "–")], ["Dernier transfert", esc(ups.LASTXFER || "–")]])}`);
    const sens = sl.sensors || {};
    setHTML($("#mm-sensors"), `<h2>Capteurs</h2><div class="tbl-wrap scroll" style="max-height:230px"><table>${Object.entries(sens).sort().map(([k, v]) => `<tr><td class="cell-sub">${esc(k.replace(/-isa-\d+|-pci-\d+|-acpi-\d+/g, ""))}</td><td class="num">${k.startsWith("fan") ? v + " tr/min" : nf1.format(v) + " °C"}</td></tr>`).join("")}</table></div>`);
    setHTML($("#mm-extra"), `<h2>Partitions système</h2><table><tr><th>Montage</th><th class="num">Utilisé</th></tr>${((SL().nas_sched || {}).df || []).map((x) => { const p = (100 * x.used) / x.size;
      return `<tr><td class="mono">${esc(x.target)}<div class="cell-sub">${esc(x.source)}</div></td><td class="num"><div class="row-flex" style="justify-content:flex-end"><div class="bar ${pctClass(p, 80, 90)}" style="width:90px"><i style="width:${p}%"></i></div>${nf0.format(p)} %</div></td></tr>`; }).join("")}</table>`);
    const notifs = (sl.notifications || []).slice().sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    setHTML($("#mm-notif"), `<h2>Notifications Unraid non lues <span class="r hint">${notifs.length}</span></h2>${notifs.map((n) => `<div class="ev"><time>${fmtDate(+n.timestamp)}</time><span class="dot ${n.importance === "alert" ? "crit" : n.importance === "warning" ? "warn" : ""}"></span><div>${esc(n.subject || n.event)}<small>${esc(n.description || "")}</small></div></div>`).join("") || '<div class="empty">Aucune</div>'}`);
  }
  setHTML($("#mm-if"), ifaceTable(m.ifaces));
}
function renderClawhost() {
  const c = L().clawhost || {}, ts = ((L().tailscale || {}).peers || []).find((p) => p.host === "clawhost") || {};
  const etc = SL().claw_etc || {}, bk = SL().nas_backups || {}, cs = SL().claw_ssh || {};
  setHTML($("#mc-head"), `<h2>clawhost · Ubuntu 24.04 <span class="r tag ${c.up ? "ok" : "crit"}">${c.up ? "en ligne" : "injoignable"}</span></h2>
    ${kv([["IP LAN", `${esc(c.ip || "")} <span class="cell-sub">(DHCP)</span>`], ["Ancienne IP", Object.entries(c.old_ip_alive || {}).map(([ip, a]) => `${ip} ${a ? "répond" : "libre"}`).join("") || "–"],
      ["Ping", c.ping != null ? nf1.format(c.ping) + " ms" : "–"], ["Tailscale", ts.online ? "en ligne" : `hors ligne${ts.last_seen ? " depuis " + fmtDate(Date.parse(ts.last_seen) / 1000, false) : ""}`],
      ["Accès SSH", c.ssh_access ? "oui, lecture seule (clé InfraDash restreinte)" : "non (sondes externes)"], ["Sauvegarde", "03:30 → NAS"],
      ...(cs.ok ? [["Système", `${esc(cs.os || "")} · noyau ${esc(cs.kernel || "")}`], ["Mises à jour", `${nf0.format(cs.n_upgradable || 0)} en attente${cs.reboot_required ? " · redémarrage requis" : ""}`],
        ["Services en échec", (cs.failed_units || []).length ? esc(cs.failed_units.join(", ")) : "aucun"]] : [])])}
    <div class="hint mt">Héberge l'agent OpenClaw (gateway :18789), Netscan (:3000, Postgres) et FitCoach (:8300, actuellement arrêté). Monte 4 partages du NAS en CIFS.</div>
    ${c.ssh_access ? "" : `<div class="hint mt"><b>Activer l'accès lecture seule</b> (métriques, mises à jour, services, conteneurs) : depuis le homelab, lancez la commande ci-dessous et saisissez une fois le mot de passe d'openclaw. Elle autorise une clé dédiée, acceptée uniquement depuis le homelab, sans terminal ni tunnel, et limitée à deux commandes de lecture. Pour la retirer, supprimez la ligne « infradash-ro@homelab » de ~/.ssh/authorized_keys sur clawhost.${cs.installed && cs.error && !/Permission denied/.test(cs.error) ? ` <span style="color:var(--warn)">Dernier essai : ${esc(cs.error)}</span>` : ""}</div>
      <div class="vuln-cmd"><pre>ssh -p 2211 openclaw@192.168.2.5 'bash -s' &lt; ~/infra-dashboard/tools/clawhost-ro-setup.sh</pre>${copyBtn("ssh -p 2211 openclaw@192.168.2.5 'bash -s' < ~/infra-dashboard/tools/clawhost-ro-setup.sh")}</div>`}`);
  setHTML($("#mc-probes"), `<table><tr><th>Service</th><th>Port</th><th>État</th><th class="num">Latence</th><th>Tendance</th></tr>${(c.probes || []).map((p, i) =>
    `<tr><td>${esc(p.name)}</td><td class="mono">${p.port}</td><td>${p.up ? `<span class="tag ok">${p.code ? "HTTP " + p.code : "ouvert"}</span>` : '<span class="tag crit">fermé</span>'}</td><td class="num">${p.ms != null ? nf1.format(p.ms) + " ms" : "–"}</td><td><canvas class="mini" data-pr="${i}"></canvas></td></tr>`).join("")}</table>`);
  $$("canvas[data-pr]").forEach((cv) => sparkline(cv, (c.probes[cv.dataset.pr] || {}).hist, "#FF375F"));
  const ch = chart($("#mc-ping"));
  const now = Date.now();
  ch && ch.setOption(baseOpt({ xAxis: { type: "category", show: false, data: (c.ping_hist || []).map((_, i) => i) }, yAxis: { type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: "{value} ms" } },
    series: [lineSeries("ping", (c.ping_hist || []).map((v) => v), "#FF375F")] }));
  setHTML($("#mc-mounts"), `<table><tr><th>Partage NAS</th><th>Point de montage</th><th>Mode</th></tr>${(etc.mounts || []).filter((m) => m.fstype === "cifs").map((m) =>
    `<tr><td class="mono">${esc(m.source)}</td><td class="mono">${esc(m.target)}</td><td>${/(^|,)ro(,|$)/.test(m.options) ? '<span class="tag info">lecture</span>' : '<span class="tag warn">lecture/écriture</span>'}</td></tr>`).join("") || '<tr><td colspan="3" class="empty">–</td></tr>'}</table>
    <div class="hint mt">Montages automatiques (x-systemd.automount). Sessions SMB actives vues par le NAS : ${((SL().nas || {}).smb_shares || []).filter((s) => s.machine === c.ip).map((s) => esc(s.share)).join(", ") || "aucune"}.</div>`);
  setHTML($("#mc-inv"), `<pre class="mono" style="white-space:pre-wrap;font-size:11.5px;color:var(--text2);max-height:300px;overflow:auto;margin:0">${esc(bk.claw_inventory || "–")}</pre>`);
  setHTML($("#mc-howto"), `<div class="howto">Ce dashboard n'a pas d'accès SSH à clawhost : il ne voit que les ports, la latence, les sauvegardes et ce que le NAS observe. Pour obtenir CPU, RAM, réseau et conteneurs en direct, autorisez la clé du homelab (lecture seule, aucune autre modification) :
    <pre>ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2211 openclaw@192.168.2.5</pre>À lancer depuis le homelab (compte jeff). Le dashboard bascule automatiquement en collecte complète dans les 10 minutes.</div>
    <div class="sep"></div><h2>Planification connue</h2>${(etc.timers || []).filter((t) => !/^(apt|snap|motd|fwupd|man-db|logrotate|e2scrub|fstrim|dpkg|systemd|update-notifier|ua-|apport|sysstat)/.test(t.unit)).map((t) => `<div class="ev"><time>${esc(t.calendar || "")}</time><span class="dot ok"></span><div>${esc(t.unit)}<small>${esc(t.desc)} — ${esc(t.exec)}</small></div></div>`).join("") || '<div class="empty">–</div>'}`);
}

/* ===================================================================== CONTENEURS */
function renderContainers(first) {
  if (!$("#ct-host").dataset.init) {
    $("#ct-host").dataset.init = 1;
    segment($("#ct-host"), (b) => { UI.ctHost = b.dataset.h; renderContainers(); });
    $("#ct-search").addEventListener("input", () => renderContainers());
    $("#ct-table").addEventListener("click", (e) => { const th = e.target.closest("th[data-k]"); if (!th) return; UI.ctSort = [th.dataset.k, UI.ctSort[0] === th.dataset.k ? -UI.ctSort[1] : -1]; renderContainers(); });
  }
  const q = $("#ct-search").value.toLowerCase();
  // Le port : un terminal par machine (ou seulement celui de l'hôte filtré)
  if (window.Harbor) {
    if (!HARBOR) HARBOR = new Harbor($("#ct-harbor"), { onSelect: (c) => { $("#ct-search").value = c.name; renderContainers(); } });
    const by = { nas: [], homelab: [], clawhost: [] };
    allContainers().forEach((c) => { if (by[c.host] && (UI.ctHost === "all" || c.host === UI.ctHost)) by[c.host].push(c); });
    HARBOR.setData(by);
    HARBOR.setFilter(q);
  }
  let list = allContainers().filter((c) => UI.ctHost === "all" || c.host === UI.ctHost)
    .filter((c) => !q || [c.name, c.image, c.project, c.cat, c.desc].join(" ").toLowerCase().includes(q));
  const [k, dir] = UI.ctSort;
  list.sort((a, b) => { const va = k === "net" ? (a.rx || 0) + (a.tx || 0) : a[k], vb = k === "net" ? (b.rx || 0) + (b.tx || 0) : b[k];
    return (typeof va === "string" ? String(va).localeCompare(vb) : (va || 0) - (vb || 0)) * dir; });
  $("#ct-count").textContent = `${list.length} conteneurs · ${list.filter((c) => c.state === "running").length} actifs`;
  const th = (key, lbl, cls = "") => `<th class="sort ${cls}" data-k="${key}">${lbl}${UI.ctSort[0] === key ? (UI.ctSort[1] > 0 ? " ↑" : " ↓") : ""}</th>`;
  const html = `<tr>${th("host", "Hôte")}${th("name", "Conteneur")}${th("project", "Projet")}<th>État</th>${th("cpu", "CPU", "num")}<th>CPU 2 min</th>${th("mem", "RAM", "num")}${th("net", "Réseau ↓/↑", "num")}<th>Trafic</th><th>Ports publiés</th></tr>` +
    list.map((c, i) => {
      const stc = c.state !== "running" ? "crit" : c.health === "unhealthy" ? "crit" : c.health === "starting" ? "warn" : "ok";
      const ports = [...new Set(((c.ports || "").match(/(?:[\d.]+:)?(\d+)->/g) || []).map((x) => x.replace("->", "")))].slice(0, 4).join(" ");
      return `<tr><td><span class="tag ${c.host === "nas" ? "" : "info"}">${esc(HOST_LABEL[c.host])}</span></td>
        <td><b>${esc(c.name)}</b><div class="cell-sub">${esc(c.desc || c.image)}</div></td><td class="cell-sub">${esc(c.project || "–")}</td>
        <td><span class="tag ${stc}">${esc(c.health && c.health !== "none" ? c.health : c.state)}</span><div class="cell-sub">${esc((c.status || "").replace(/\(.*?\)/, "").trim())}</div></td>
        <td class="num">${c.cpu != null ? fmtPct(c.cpu) : "–"}</td><td><canvas class="mini" data-sp="${i}"></canvas></td><td class="num">${c.mem ? fmtBytes(c.mem) : "–"}</td>
        <td class="num">${c.rx != null ? `${fmtRate(c.rx)}<div class="cell-sub">${fmtRate(c.tx)}</div>` : "–"}</td><td><canvas class="mini" data-np="${i}"></canvas></td><td class="mono cell-sub">${esc(ports)}</td></tr>`;
    }).join("");
  const t = $("#ct-table"); t.innerHTML = html;
  $$("canvas[data-sp]", t).forEach((cv) => sparkline(cv, list[cv.dataset.sp].spark, CAT_COLOR[list[cv.dataset.sp].cat] || "#64D2FF", { min: 5 }));
  $$("canvas[data-np]", t).forEach((cv) => sparkline(cv, list[cv.dataset.np].nspark, "#BF5AF2", { min: 1000 }));
}

/* ===================================================================== PLANNING */
function renderPlanning(first) {
  const jobs = jobsList(), J = D().jobs || {};
  if (!$("#pl-host").dataset.init) {
    $("#pl-host").dataset.init = 1;
    segment($("#pl-host"), (b) => { UI.plHost = b.dataset.h; renderPlanning(true); });
    $("#pl-search").addEventListener("input", () => renderPlanning(true));
    $("#pl-cat").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; UI.plCat = b.dataset.c; renderPlanning(true); });
  }
  const cats = [...new Set(jobs.map((j) => j.cat))];
  setHTML($("#pl-cat"), `<button data-c="all" class="${UI.plCat === "all" ? "on" : ""}">Toutes</button>` + cats.map((c) => `<button data-c="${c}" class="${UI.plCat === c ? "on" : ""}">${JOB_LABEL[c] || c}</button>`).join(""));
  const now = Date.now() / 1000;
  const enabled = jobs.filter((j) => j.enabled);
  const runs = enabled.filter((j) => (j.per_day || 0) <= 30).reduce((a, j) => a + (j.runs24 || []).length, 0);
  const nb = enabled.filter((j) => j.cat === "backup" && j.next).sort((a, b) => a.next - b.next)[0];
  const peak = (J.peak || [])[0];
  setHTML($("#pl-kpis"), [["Tâches", jobs.length, `${enabled.length} actives · ${jobs.length - enabled.length} désactivées`, "var(--violet)"],
    ["Exécutions 24 h", runs, `+ ${enabled.filter((j) => (j.per_day || 0) > 30).length} tâches en continu`, "var(--cyan)"],
    ["Prochaine sauvegarde", nb ? `<span data-cd="${nb.next}">${fmtCountdown(nb.next - now)}</span>` : "–", nb ? `${esc(nb.title)} · ${fmtTime(nb.next)}` : "", "var(--green)"],
    ["Heure de pointe", peak ? peak[0] : "–", peak ? `${peak[1].length} tâches lourdes` : "", "var(--amber)"],
    ["Par machine", `${jobs.filter((j) => j.host === "nas").length}<small>NAS</small> ${jobs.filter((j) => j.host === "homelab").length}<small>HL</small> ${jobs.filter((j) => j.host === "clawhost").length}<small>CH</small>`, "NAS · homelab · clawhost", "var(--pink)"]]
    .map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
  if (first || !UI.ganttT || Date.now() - UI.ganttT > 30000) { UI.ganttT = Date.now(); renderGantt(enabled); renderHeat(J.week); }
  const q = $("#pl-search").value.toLowerCase();
  const list = jobs.filter((j) => (UI.plHost === "all" || j.host === UI.plHost) && (UI.plCat === "all" || j.cat === UI.plCat) && (!q || [j.title, j.desc, j.command].join(" ").toLowerCase().includes(q)));
  setHTML($("#pl-table"), `<tr><th>Machine</th><th>Tâche</th><th>Quand</th><th>Prochaine</th><th>Précédente</th><th>Source</th></tr>` + list.map((j) => `<tr style="${j.enabled ? "" : "opacity:.5"}">
    <td><span class="tag ${j.host === "nas" ? "" : j.host === "homelab" ? "info" : "warn"}">${esc(HOST_LABEL[j.host])}</span></td>
    <td><b style="color:${JOB_COLOR[j.cat] || "#fff"}">●</b> <b>${esc(j.title)}</b>${j.verified === false ? ' <span class="tag mute" title="Lu dans une sauvegarde ou à l\'installation">non vérifié en direct</span>' : ""}<div class="cell-sub">${esc(j.desc || "")}</div><div class="cell-sub mono" style="font-size:11px;opacity:.75">${esc((j.command || "").slice(0, 140))}</div>${j.note ? `<div class="cell-sub" style="font-size:11px">${esc(j.note)}</div>` : ""}</td>
    <td>${esc(j.human || "")}${j.schedule ? `<div class="cell-sub mono">${esc(j.schedule)}</div>` : ""}</td>
    <td class="mono">${j.next ? `${fmtDate(j.next)}<div class="cell-sub" data-cd="${j.next}">${fmtCountdown(j.next - now)}</div>` : "–"}</td>
    <td class="mono cell-sub">${j.prev ? fmtDate(j.prev) : "–"}</td><td class="cell-sub">${esc(j.source)}<div>${esc(j.user || "")}</div></td></tr>`).join(""));
}
function renderGantt(jobs) {
  const el = $("#pl-gantt"), now = Date.now() / 1000, span = 86400;
  const rows = jobs.filter((j) => (j.per_day || 0) <= 30 && (j.runs24 || []).length).sort((a, b) => (a.host + a.runs24[0]).localeCompare(b.host + b.runs24[0]));
  const W = Math.max(760, el.clientWidth || 760), lw = 200, rh = 22, top = 26, H = top + rows.length * rh + 30;
  const x = (t) => lw + ((t - now) / span) * (W - lw - 14);
  let g = "";
  const start = new Date(); start.setMinutes(0, 0, 0);
  for (let h = 1; h <= 24; h++) {
    const t = start.getTime() / 1000 + h * 3600; if (t - now > span) break;
    const xx = x(t), hr = new Date(t * 1000).getHours();
    g += `<line x1="${xx}" y1="${top - 6}" x2="${xx}" y2="${H - 24}" stroke="rgba(255,255,255,${hr % 6 ? 0.04 : 0.1})"/>`;
    if (hr % 3 === 0) g += `<text x="${xx}" y="${top - 10}" text-anchor="middle" style="font-family:var(--mono);fill:#8E8E93">${String(hr).padStart(2, "0")}h</text>`;
  }
  let lastHost = "";
  rows.forEach((j, i) => {
    const y = top + i * rh + rh / 2, col = JOB_COLOR[j.cat] || "#8E8E93";
    if (j.host !== lastHost) { g += `<line x1="0" y1="${y - rh / 2}" x2="${W}" y2="${y - rh / 2}" stroke="rgba(255,255,255,.08)"/>`; lastHost = j.host; }
    g += `<text x="6" y="${y + 4}"><tspan style="fill:${j.host === "nas" ? "#BF5AF2" : j.host === "homelab" ? "#64D2FF" : "#FF375F"};font-weight:600">${esc(HOST_LABEL[j.host].slice(0, 3).toUpperCase())}</tspan> ${esc(j.title.slice(0, 26))}</text>`;
    g += `<line x1="${lw}" y1="${y}" x2="${W - 14}" y2="${y}" stroke="${col}" stroke-opacity=".08" stroke-width="8" stroke-linecap="round"/>`;
    (j.runs24 || []).forEach((r) => {
      const heavy = ["backup", "stockage", "media"].includes(j.cat);
      g += `<circle cx="${x(r)}" cy="${y}" r="${heavy ? 5.5 : 4}" fill="${col}"><title>${fmtDate(r)} · ${esc(j.title)}</title></circle>`;
    });
  });
  g += `<line x1="${lw}" y1="${top - 8}" x2="${lw}" y2="${H - 24}" stroke="#64D2FF" stroke-width="2"/><text x="${lw + 4}" y="${H - 10}" style="fill:#64D2FF;font-weight:600">maintenant</text>`;
  el.innerHTML = `<svg width="${W}" height="${H}">${g}</svg>`;
  setHTML($("#pl-legend"), Object.entries(JOB_LABEL).filter(([k]) => jobs.some((j) => j.cat === k)).map(([k, l]) => `<span><i style="background:${JOB_COLOR[k]}"></i>${l}</span>`).join(""));
}
function renderHeat(week) {
  if (!week) return;
  const days = ["lun", "mar", "mer", "jeu", "ven", "sam", "dim"];
  const data = []; let max = 1;
  week.forEach((row, d) => row.forEach((v, h) => { data.push([h, d, v || null]); max = Math.max(max, v); }));
  const c = chart($("#pl-heat"));
  c && c.setOption(baseOpt({ grid: { left: 40, right: 10, top: 10, bottom: 50 }, tooltip: { trigger: "item", backgroundColor: "rgba(35,35,37,.97)", borderColor: "#313134", textStyle: { color: "#F5F5F7" },
      formatter: (p) => `${days[p.value[1]]} ${String(p.value[0]).padStart(2, "0")}h : <b>${p.value[2] || 0}</b> exécution(s)` },
    xAxis: { type: "category", data: [...Array(24).keys()].map((h) => h + "h"), ...AX, splitArea: { show: false } },
    yAxis: { type: "category", data: days, ...AX, inverse: true },
    visualMap: { min: 0, max, show: true, orient: "horizontal", left: "center", bottom: 0, itemHeight: 120, textStyle: { color: "#8E8E93" }, inRange: { color: ["#2C2C2E", "#1D3A5C", "#2F6DB5", "#4A9EFF", "#A8D1FF"] } },
    series: [{ type: "heatmap", data, itemStyle: { borderColor: "#1C1C1E", borderWidth: 2, borderRadius: 4 }, emphasis: { itemStyle: { borderColor: "#f5f5f7", borderWidth: 1 } } }] }), true);
}

/* ===================================================================== STOCKAGE */
function renderStorage(first) {
  const sl = SL().nas || {}, m = L().nas || {}, arr = m.array || {}, disks = sl.disks || {};
  const order = ["parity", "parity2", ...Object.keys(disks).filter((k) => /^disk\d+$/.test(k)).sort((a, b) => +a.slice(4) - +b.slice(4)), "cache"];
  const checking = +arr.mdResyncPos > 0;
  const el = $("#st-array");
  el.classList.toggle("checking", checking);
  if (!el.dataset.k || el.dataset.k !== order.join()) {
    el.dataset.k = order.join();
    el.innerHTML = order.filter((k) => disks[k]).map((k) => `<div class="drive ${k.startsWith("parity") ? "parity" : k === "cache" ? "cache" : ""}" data-d="${k}"><div class="body"><div class="fill"></div><div class="scan"></div><div class="leds"><span class="led r"></span><span class="led w"></span></div><div class="pct"></div></div><div class="nm">${k}</div><div class="tp"></div></div>`).join("");
  }
  const cacheDf = ((SL().nas_sched || {}).df || []).find((x) => x.target === "/mnt/cache");
  $$(".drive", el).forEach((dv) => {
    const k = dv.dataset.d, d = disks[k] || {}, io = (m.disks || {})[d.device] || {};
    let pct = d.fsSize ? 100 * (1 - d.fsFree / d.fsSize) : null;
    if (k === "cache" && cacheDf) pct = (100 * cacheDf.used) / cacheDf.size;
    if (pct != null) { dv.querySelector(".fill").style.height = pct + "%"; dv.querySelector(".pct").textContent = nf0.format(pct) + " %"; }
    else dv.querySelector(".pct").textContent = k.startsWith("parity") ? "P" + (k === "parity2" ? "2" : "1") : "";
    const sizeTB = (+d.size * 1024) / 1e12;
    dv.querySelector(".tp").innerHTML = `${esc(d.temp || "*")}°C · ${nf1.format(sizeTB)} To<br><span style="color:${d.status === "DISK_OK" ? "var(--ok)" : "var(--crit)"}">${esc(d.device || "")}</span>`;
    dv.querySelector(".tp").style.color = +d.temp >= 45 ? "var(--warn)" : "";
    dv.querySelector(".led.r").classList.toggle("on", io.read > 5e5);
    dv.querySelector(".led.w").classList.toggle("on", io.write > 2e5);
    dv.title = `${k} (${d.device}) · lecture ${fmtRate(io.read)} · écriture ${fmtRate(io.write)} · occupé ${io.busy || 0} %`;
  });
  setHTML($("#st-array-state"), `<span class="tag ${arr.mdState === "STARTED" ? "ok" : "crit"}">${esc(arr.mdState || "–")}</span> <span class="tag">${arr.mdNumDisks || "?"} disques</span> <span class="tag ${arr.shareMoverActive === "yes" ? "warn" : "mute"}">mover ${arr.shareMoverActive === "yes" ? "actif" : "inactif"}</span>`);
  const last = +arr.sbSynced ? new Date(arr.sbSynced * 1000) : null;
  let ph = "";
  if (checking) {
    const pos = +arr.mdResyncPos, size = +(arr.mdResyncSize || arr.mdResync), pct = (100 * pos) / size;
    const inst = +arr.mdResyncDt ? (+arr.mdResyncDb / +arr.mdResyncDt) * 1024 : null;
    const el2 = last ? Date.now() / 1000 - arr.sbSynced : 0;
    const speed = el2 > 600 ? (pos * 1024) / el2 : inst;
    const eta = speed ? ((size - pos) * 1024) / speed : null;
    ph = `<div class="row-flex" style="justify-content:space-between;margin-bottom:8px;flex-wrap:wrap"><b>Contrôle de parité en cours · ${nf1.format(pct)} %</b><span class="mono">moy. ${speed ? fmtRate(speed) : "–"} · instant. ${inst ? fmtRate(inst) : "–"} · fin estimée ${eta ? fmtDate(Date.now() / 1000 + eta) : "–"} (${eta ? fmtDur(eta) : "–"})</span></div><div class="progress"><i style="width:${pct}%"></i></div>
      <div class="hint mt">Démarré ${last ? "le " + last.toLocaleString("fr-FR") : ""} · ${fmtBytes(pos * 1024)} lus sur ${fmtBytes(size * 1024)} par disque · erreurs corrigées jusqu'ici : ${esc(arr.sbSyncErrs || "0")}.</div>`;
  } else ph = `<div class="hint">Dernier contrôle : ${last ? last.toLocaleString("fr-FR") : "–"} · erreurs : ${esc(arr.sbSyncErrs || "0")} · prochain : le 6 du mois à 10:00.</div>`;
  setHTML($("#st-parity"), ph);
  const plog = (SL().nas_sched || {}).parity_log || [];
  if (first || !UI.stT || Date.now() - UI.stT > 60000) {
    UI.stT = Date.now();
    const c = chart($("#st-parity-ch"));
    c && c.setOption(baseOpt({ grid: { left: 40, right: 40, top: 30, bottom: 26 }, xAxis: { type: "category", data: plog.map((p) => p.date.slice(0, 11)), ...AX }, yAxis: [{ type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: "{value} h" } }, { type: "value", ...AX, splitLine: { show: false } }],
      series: [{ name: "Durée (h)", type: "bar", data: plog.map((p) => +(p.duration / 3600).toFixed(1)), itemStyle: { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: "#BF5AF2" }, { offset: 1, color: "#BF5AF222" }]), borderRadius: [6, 6, 0, 0] } },
        { name: "Erreurs", type: "line", yAxisIndex: 1, data: plog.map((p) => p.errors), lineStyle: { color: "#FF453A", width: 2 }, itemStyle: { color: "#FF453A" }, symbolSize: 8 }] }), true);
    history("disk_temp", "nas", "24h").then((h) => {
      const c2 = chart($("#st-temps-ch")); if (!c2) return;
      const ser = (h.series || []).map((s, i) => lineSeries(s.labels.disk, s.values.map(([t, v]) => [t * 1000, v]), ["#64D2FF", "#BF5AF2", "#FF375F", "#FF9F0A", "#A3D977", "#4A9EFF", "#FF6482", "#66D4CF", "#7D7AFF", "#FFD60A"][i % 10], false));
      if (ser.length && ser[0].data.length > 3) c2.setOption(baseOpt({ legend: { show: false }, xAxis: { type: "time", ...AX, splitLine: { show: false } }, yAxis: { type: "value", ...AX, min: (v) => Math.floor(v.min - 2) }, series: ser }), true);
      else c2.setOption(baseOpt({ legend: { show: false }, grid: { left: 60, right: 20, top: 10, bottom: 26 }, xAxis: { type: "value", ...AX, max: 55 }, yAxis: { type: "category", data: order.filter((k) => disks[k]), ...AX },
        series: [{ type: "bar", data: order.filter((k) => disks[k]).map((k) => ({ value: +disks[k].temp || 0, itemStyle: { color: +disks[k].temp >= 45 ? "#FF9F0A" : "#64D2FF", borderRadius: 6 } })), label: { show: true, position: "right", color: "#C7C7CC", formatter: "{c} °C" } }] }), true);
    });
  }
  const shares = Object.values(sl.shares || {}).filter((s) => s.name);
  const cacheTxt = { yes: "écrit sur le cache puis déplacé par le mover (04:00)", prefer: "reste sur le cache NVMe", only: "cache uniquement", no: "écrit directement sur l'array" };
  setHTML($("#st-shares"), `<tr><th>Partage</th><th>Cache NVMe</th><th>Comportement</th><th>Allocation</th></tr>` + shares.sort((a, b) => a.name.localeCompare(b.name)).map((s) =>
    `<tr><td><b>${esc(s.name)}</b><div class="cell-sub">${esc(s.comment || "")}</div></td><td><span class="tag ${s.useCache === "yes" ? "warn" : s.useCache === "only" || s.useCache === "prefer" ? "info" : "mute"}">${esc(s.useCache || "no")}</span></td><td class="cell-sub">${esc(cacheTxt[s.useCache] || "")}</td><td class="cell-sub">${esc(s.allocator || "")}</td></tr>`).join(""));
  const smb = sl.smb_shares || [], users = sl.smb_users || [];
  const lan = Object.fromEntries(((SL().lan || {}).devices || []).map((d) => [d.ip, d.name || d.vendor]));
  const hlm = ((SL().homelab || {}).mounts || []).filter((x) => /cifs|nfs|smb/.test(x.fstype));
  const cm = ((SL().claw_etc || {}).mounts || []).filter((x) => x.fstype === "cifs");
  setHTML($("#st-mounts"), `<h3 style="margin-top:0">Sessions SMB actives sur le NAS</h3><table><tr><th>Machine</th><th>Utilisateur</th><th>Partages ouverts</th></tr>${[...new Set(smb.map((s) => s.machine).concat(users.map((u) => u.machine)))].map((mc) =>
    `<tr><td class="mono">${esc(mc)}<div class="cell-sub">${esc(mc === "192.168.2.5" ? "clawhost" : mc === "192.168.2.4" ? "homelab" : lan[mc] || "")}</div></td><td>${[...new Set(users.filter((u) => u.machine === mc).map((u) => u.user))].map((u) => `<span class="tag">${esc(u)}</span>`).join(" ")}</td><td>${smb.filter((s) => s.machine === mc).map((s) => `<span class="tag info">${esc(s.share)}</span>`).join(" ")}</td></tr>`).join("") || '<tr><td colspan="3" class="empty">Aucune session</td></tr>'}</table>
    <h3 class="mt">clawhost → NAS (fstab)</h3><table>${cm.map((x) => `<tr><td class="mono">${esc(x.source)}</td><td>→</td><td class="mono">${esc(x.target)}</td><td>${/(^|,)ro(,|$)/.test(x.options) ? '<span class="tag info">ro</span>' : '<span class="tag warn">rw</span>'}</td></tr>`).join("")}</table>
    <h3 class="mt">Homelab → NAS</h3><div class="hint">${hlm.length ? hlm.map((x) => esc(x.source + " → " + x.target)).join("<br>") : "Aucun montage permanent : //192.168.2.3/backups est monté en CIFS (SMB 3.0) seulement pendant la sauvegarde de 03:30, sur /mnt/nas-backup."}</div>`);
}

/* ===================================================================== SAUVEGARDES */
function renderBackups(first) {
  const b = D().backups || {}, chains = b.chains || [];
  if (first || Date.now() - (UI.bkT || 0) > 10000) { UI.bkT = Date.now(); backupPipe($("#bk-pipe"), chains, S.topology); }
  const jobs = jobsList();
  const jobFor = { homelab: "Sauvegarde homelab", clawhost: "Sauvegarde clawhost", forgejo: "Sauvegarde Forgejo" };
  setHTML($("#bk-cards"), chains.map((c) => {
    const j = jobs.find((x) => x.title === jobFor[c.id]);
    return `<div class="card bk-card"><div class="top-l"><span class="dot ${c.status}"></span><b>${esc(c.label)}</b><span class="tag ${c.status}" style="margin-left:auto">${c.status === "ok" ? "à jour" : c.status === "warn" ? "en retard" : c.last_time ? "périmée" : "absente"}</span></div>
      <div class="age" style="color:${lvlColor(c.status)}">${c.last_time ? fmtDur(Date.now() / 1000 - c.last_time) : "—"}</div><div class="cell-sub">${c.last_time ? "depuis la dernière (" + fmtDate(c.last_time) + ")" : esc(c.problem || "aucune archive trouvée")}</div>
      <dl><dt>Contenu</dt><dd>${esc(c.src)}</dd><dt>Destination</dt><dd>${esc(c.dest)}</dd><dt>Planif.</dt><dd>${esc(c.when)}${j && j.next ? ` · prochaine dans <span data-cd="${j.next}">${fmtCountdown(j.next - Date.now() / 1000)}</span>` : ""}</dd>
      <dt>Méthode</dt><dd>${esc(c.method)}</dd><dt>Dernière</dt><dd>${c.last_size ? fmtBytes(c.last_size) : "–"}${c.size_delta != null ? ` <span class="cell-sub">(${c.size_delta > 0 ? "+" : ""}${nf0.format(c.size_delta)} % vs moy.)</span>` : ""}</dd>
      <dt>Stock</dt><dd>${c.count} archive(s) · ${fmtBytes(c.total)}</dd>${c.last_files ? `<dt>Fichiers</dt><dd class="mono" style="font-size:11px">${esc(c.last_files.join(" "))}</dd>` : ""}</dl></div>`; }).join(""));
  if (first || Date.now() - (UI.bkC || 0) > 60000) {
    UI.bkC = Date.now();
    const c = chart($("#bk-sizes"));
    const cols = { homelab: "#64D2FF", clawhost: "#FF375F", forgejo: "#A3D977", appdata: "#FF9F0A" };
    c && c.setOption(baseOpt({ xAxis: { type: "time", ...AX, splitLine: { show: false } }, yAxis: { type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: (v) => fmtBytes(v, 0) } },
      tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => fmtBytes(v) },
      series: chains.filter((x) => x.sizes.length).map((x) => lineSeries(x.label, x.sizes.map(([t, s]) => [t * 1000, s]), cols[x.id], true, { showSymbol: true, symbolSize: 5, smooth: false, step: false })) }), true);
  }
  const lg = b.legacy || {};
  const items = [
    ["3 copies des données", chains.filter((c) => c.status !== "crit").length >= 3 ? "partiel" : "non", "Original + archive NAS ; le homelab garde en plus 7 archives locales."],
    ["2 supports différents", "partiel", "Le homelab (NVMe) et le NAS (array) pour la chaîne homelab ; clawhost et Forgejo n'ont qu'une copie, sur le NAS."],
    ["1 copie hors site", "non", "Aucune réplication externe : un sinistre sur le NAS emporte toutes les sauvegardes."],
    ["Appdata du NAS", chains.find((c) => c.id === "appdata")?.status === "ok" ? "oui" : "non", "Vaultwarden, Immich, bases Postgres des applis : le plugin Appdata Backup est installé mais pas configuré, le User Script est désactivé."],
    ["Test de restauration", "inconnu", "Restauration de l'archive homelab testée lors de sa mise en place (bases SQLite intègres)."],
  ];
  setHTML($("#bk-321"), items.map(([k, v, d]) => `<div class="ins ${v === "non" ? "crit" : v === "oui" ? "info" : "warn"}"><div class="ii">${icon(v === "non" ? "x" : v === "oui" ? "info" : "alert")}</div><div><b>${k} : ${v}</b><p>${d}</p></div></div>`).join("") +
    (lg.duplicati_files ? `<div class="hint mt">À la racine du partage : ${lg.duplicati_files} anciens fichiers (Duplicati de juillet 2025, apitable), ${fmtBytes(lg.duplicati_size)}, plus mis à jour depuis ${lg.newest ? fmtDate(lg.newest, false) : "?"}.</div>` : ""));
}

/* ===================================================================== RÉSEAU */
function renderNetwork(first) {
  const ts = L().tailscale || {}, lat = L().latency || {}, sp = SL().speedtest || {}, dns = L().dns || {}, wan = SL().wan || {};
  const pub = (SL().public || {}).endpoints || [], lan = SL().lan || {};
  setHTML($("#nw-kpis"), [["IP publique", esc(wan.ip || "–"), wan.domain_ip && wan.domain_ip !== wan.ip ? `⚠ ${esc(wan.domain || "")} → ${esc(wan.domain_ip)}` : `${esc(wan.domain || "*.jposyno.eu")} pointe ici`, "var(--cyan)"],
    ["Download", sp.download ? `${nf0.format(sp.download / 1e6)}<small>Mb/s</small>` : "–", `upload ${sp.upload ? nf0.format(sp.upload / 1e6) : "–"} Mb/s`, "var(--green)"],
    ["Ping Internet", lat.internet && lat.internet.ms != null ? `${nf1.format(lat.internet.ms)}<small>ms</small>` : "–", `1.1.1.1 · pertes ${lat.internet ? lat.internet.loss : "–"} %`, "var(--pink)"],
    ["DNS AdGuard", dns.ok ? `${dns.ms}<small>ms</small>` : "KO", dns.blocking ? "blocage pub actif" : "blocage ?", "var(--violet)"],
    ["Tailscale", `${(ts.peers || []).filter((p) => p.online).length}<small>/ ${(ts.peers || []).length}</small>`, "pairs en ligne", "var(--violet)"],
    ["Appareils LAN", lan.count || "–", "vus dans la table ARP", "var(--teal)"],
    ["Domaines publics", `${pub.filter((p) => p.ok).length}<small>/ ${pub.length}</small>`, "via Nginx Proxy Manager", pub.some((p) => !p.ok) ? "var(--red)" : "var(--green)"]]
    .map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val" style="font-size:${String(v).length > 11 && !String(v).includes("<") ? 20 : 25}px">${v}</div><div class="foot">${f}</div></div>`).join(""));
  const c = chart($("#nw-lat"));
  const cols = { box: "#4A9EFF", nas: "#BF5AF2", clawhost: "#FF375F", internet: "#64D2FF" }, nm = { box: "Routeur", nas: "NAS", clawhost: "clawhost", internet: "Internet (1.1.1.1)" };
  const n = Math.max(...Object.values(lat).map((v) => (v.hist || []).length), 0);
  c && c.setOption(baseOpt({ xAxis: { type: "category", data: [...Array(n).keys()].map((i) => `-${(n - i) * 10}s`), ...AX, axisLabel: { show: false } }, yAxis: { type: "log", ...AX, axisLabel: { ...AX.axisLabel, formatter: "{value} ms" } },
    tooltip: { ...baseOpt().tooltip, valueFormatter: (v) => (v == null ? "perdu" : nf1.format(v) + " ms") },
    series: Object.entries(lat).map(([k, v]) => lineSeries(nm[k] || k, v.hist || [], cols[k] || "#fff", false, { connectNulls: false })) }));
  if (first || Date.now() - (UI.spT || 0) > 60000) {
    UI.spT = Date.now();
    const c2 = chart($("#nw-speed"));
    const conv = (arr) => (arr || []).map(([t, v]) => [t * 1000, +(v / 1e6).toFixed(1)]);
    c2 && c2.setOption(baseOpt({ grid: { left: 72, right: 44, top: 30, bottom: 26 }, xAxis: TAX, yAxis: [{ type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: "{value} Mb/s" } }, { type: "value", ...AX, splitLine: { show: false }, axisLabel: { ...AX.axisLabel, formatter: "{value} ms" } }],
      series: [lineSeries("Download", conv(sp.hist_dl), "#30D158"), lineSeries("Upload", conv(sp.hist_ul), "#64D2FF"), lineSeries("Ping", (sp.hist_ping || []).map(([t, v]) => [t * 1000, +(+v).toFixed(1)]), "#FF375F", false, { yAxisIndex: 1 })] }), true);
  }
  setHTML($("#nw-public"), `<tr><th>Domaine</th><th>Backend</th><th>HTTP</th><th class="num">Temps</th><th>Certificat TLS</th></tr>` + pub.slice().sort((a, b) => a.ok - b.ok || a.domain.localeCompare(b.domain)).map((e) =>
    `<tr><td><a href="https://${esc(e.domain)}" target="_blank" rel="noopener">${esc(e.domain)}</a></td><td class="mono">${esc(e.backend)}:${esc(e.port)}<div class="cell-sub">${esc(e.backend_host === "clawhost-old" ? "⚠ ancienne IP de clawhost" : e.backend_host || "")}</div></td>
      <td><span class="tag ${e.ok ? "ok" : "crit"}">${e.code || "timeout"}</span></td><td class="num">${e.ms} ms</td>
      <td>${e.cert_days != null ? `<span class="tag ${e.cert_days < 15 ? "warn" : "ok"}">${e.cert_days} j</span> <span class="cell-sub">${esc(e.issuer || "")}</span>` : `<span class="cell-sub">${esc(e.issuer || "–")}</span>`}</td></tr>`).join(""));
  $("#nw-ts-sub").textContent = ts.tailnet ? `${ts.tailnet} · ${ts.self ? ts.self.host : ""}` : "";
  setHTML($("#nw-ts"), `<tr><th>Machine</th><th>Statut</th><th>Liaison</th><th class="num">Débit</th><th>Clé expire</th></tr>` + (ts.peers || []).map((p) => {
    const exp = p.key_expiry ? (Date.parse(p.key_expiry) - Date.now()) / 86400000 : null;
    return `<tr><td><b>${esc(p.dns || p.host)}</b><div class="cell-sub mono">${esc(p.ip)} · ${esc(p.os || "")}</div></td><td>${p.online ? '<span class="tag ok">en ligne</span>' : `<span class="tag mute">hors ligne</span><div class="cell-sub">${p.last_seen ? fmtDate(Date.parse(p.last_seen) / 1000, false) : ""}</div>`}</td>
      <td class="cell-sub">${p.online ? (p.direct ? "direct " + esc(p.addr) : "relais " + esc(p.relay)) : "–"}</td><td class="num">${p.online ? `↓${fmtRate(p.rx)}<div class="cell-sub">↑${fmtRate(p.tx)}</div>` : "–"}</td>
      <td>${exp == null ? "–" : `<span class="tag ${exp < 0 ? "crit" : exp < 30 ? "warn" : "mute"}">${exp < 0 ? "expirée" : nf0.format(exp) + " j"}</span>`}</td></tr>`; }).join(""));
  $("#nw-lan-sub").textContent = `${lan.count || 0} appareils`;
  setHTML($("#nw-lan"), `<tr><th>IP</th><th>Nom / fabricant</th><th>MAC</th><th>État</th></tr>` + (lan.devices || []).filter((d) => d.mac).map((d) =>
    `<tr><td class="mono">${esc(d.ip)}</td><td>${esc(d.name || "")}<div class="cell-sub">${esc(d.vendor || "")}</div></td><td class="mono cell-sub">${esc(d.mac)}</td><td><span class="tag ${d.state === "REACHABLE" ? "ok" : "mute"}">${esc(d.state.toLowerCase())}</span></td></tr>`).join(""));
  const c3 = chart($("#nw-dns"));
  c3 && c3.setOption(baseOpt({ grid: { left: 48, right: 16, top: 16, bottom: 24 }, xAxis: { type: "time", ...AX, splitLine: { show: false } }, yAxis: { type: "value", ...AX, axisLabel: { ...AX.axisLabel, formatter: "{value} ms" } },
    series: [lineSeries("Résolution DNS", (L().dns_hist || []).map(([t, v]) => [t * 1000, v]), "#FF375F")] }));
}

/* ===================================================================== DIAGNOSTICS & JOURNAL */
function renderInsights() {
  if (!$("#in-filter").dataset.init) { $("#in-filter").dataset.init = 1; segment($("#in-filter"), (b) => { UI.inLevel = b.dataset.l; renderInsights(); }); }
  const ins = (D().insights || []).filter((i) => UI.inLevel === "all" || i.level === UI.inLevel);
  setHTML($("#in-list"), ins.map(insightHTML).join("") || '<div class="empty">Rien dans cette catégorie</div>');
  const names = { "homelab.fast": "Homelab /proc (2 s)", "homelab.containers": "Homelab cAdvisor (5 s)", "homelab.slow": "Homelab crons/timers/montages", "homelab.dns": "Test DNS AdGuard",
    "homelab.apt": "Mises à jour apt (simulation)", "nas.fast": "NAS /proc + cgroups + sockets (3 s)", "nas.slow": "NAS Docker, disques, UPS, GPU", "nas.conntrack": "NAS conntrack (10 s)",
    "nas.sched": "NAS crons, User Scripts, NPM", "nas.backups": "Inventaire des sauvegardes", "nas.claw_etc": "clawhost /etc (sauvegarde)", "clawhost.probes": "clawhost sondes (10 s)",
    "net.tailscale": "Tailscale", "net.lan": "Voisins ARP", "net.latency": "Latences", "net.public": "Domaines publics + TLS", "net.wan": "IP publique", "net.speedtest": "Speedtest (VictoriaMetrics)",
    "derived.fast": "Calcul des flux", "derived.slow": "Planning, sauvegardes, diagnostics", "vm.push": "Écriture VictoriaMetrics" };
  setHTML($("#in-coll"), `<tr><th>Collecteur</th><th>État</th><th class="num">Durée</th><th class="num">Exéc.</th><th>Dernière</th></tr>` + Object.entries(S.collectors || {}).sort().map(([k, v]) =>
    `<tr><td>${esc(names[k] || k)}<div class="cell-sub mono">${esc(k)}</div>${v.last_error && !v.ok ? `<div class="cell-sub" style="color:var(--crit)">${esc(v.last_error)}</div>` : ""}</td><td><span class="tag ${v.ok ? "ok" : "crit"}">${v.ok ? "ok" : "erreur"}</span></td>
    <td class="num">${v.dur_ms != null ? v.dur_ms + " ms" : "–"}</td><td class="num">${v.runs}${v.errors ? `<div class="cell-sub">${v.errors} err.</div>` : ""}</td><td class="cell-sub">${ago(v.last)}</td></tr>`).join(""));
}
function renderJournal() {
  if (!$("#jr-filter").dataset.init) { $("#jr-filter").dataset.init = 1; segment($("#jr-filter"), (b) => { UI.jrHost = b.dataset.h; renderJournal(); }); }
  const ev = (S.events || []).filter((e) => UI.jrHost === "all" || e.host === UI.jrHost).slice().reverse();
  setHTML($("#jr-list"), ev.map((e) => eventHTML(e)).join("").replace(/<time>([^<]+)<\/time>/g, (m, t) => m) || '<div class="empty">Aucun événement pour l\'instant. Le journal se remplit au fil des changements détectés (et persiste entre les redémarrages).</div>');
}

/* ===================================================================== ORCHESTRATION */
/* ===================================================================== VULNÉRABILITÉS */
const PRIO = { critique: ["crit", 0], haute: ["warn", 1], moyenne: ["info", 2], basse: ["mute", 3] };
const EXPO = { internet: ["crit", "Internet"], lan: ["warn", "LAN"], local: ["ok", "local"], inconnue: ["mute", "?"] };
const VU = { full: null, t: 0, loading: false, host: "all", prio: "all", open: new Set() };
async function loadVulns(force) {
  if (VU.loading) { if (force) VU.again = true; return; }
  if (!force && VU.full && Date.now() - VU.t < 60000) return;
  VU.loading = true;
  let ok = false;
  try { VU.full = await (await fetch("/api/vulns", { cache: "no-store" })).json(); VU.t = Date.now(); ok = true; } catch (e) { /* réessai au prochain tick du flux (20 s) */ }
  VU.loading = false;
  if (VU.again) { VU.again = false; return loadVulns(true); }   // données d'avant la fin d'une revérification
  if (ok && CURRENT === "vulns") renderVulns(false);   // rendu sans rechargement forcé (sinon boucle de GET /api/vulns)
}
const prioTag = (p) => `<span class="tag ${(PRIO[p] || ["mute"])[0]}">${esc(p || "–")}</span>`;
const expoTag = (e) => `<span class="tag ${(EXPO[e] || EXPO.inconnue)[0]}" title="Exposition">${esc((EXPO[e] || EXPO.inconnue)[1])}</span>`;
function copyBtn(txt) { return `<button class="btn ghost copy" data-copy="${esc(txt)}" title="Copier">Copier</button>`; }
/* Revérification après correction : inventaire des 3 machines + analyse complète, bilan avant / après */
const VR = { st: null, msg: "", until: 0, polling: false, hide: 0 };
try { VR.hide = +localStorage.getItem("infradash.vr-hide") || 0; } catch (e) { /* stockage indisponible */ }
function vrState() {
  const a = VR.st || {}, b = D().vulns_refresh || {};
  const t = (x) => Math.max(x.started || 0, x.finished || 0);
  return t(a) >= t(b) ? a : b;
}
async function pollRefresh() {
  if (VR.polling) return;
  VR.polling = true;
  try {
    for (let i = 0; i < 240; i++) {
      await new Promise((r) => setTimeout(r, 2000));
      try { VR.st = await (await fetch("/api/vulns/refresh", { cache: "no-store" })).json(); } catch (e) { continue; }
      if (CURRENT === "vulns") renderVuRefresh();
      if (VR.st.status !== "en_cours") break;
    }
  } finally { VR.polling = false; }
  if (VR.st && VR.st.status !== "en_cours") VR.msg = "";
  await loadVulns(true);
  if (CURRENT === "vulns") { renderVulns(false); if (VR.scroll) vrScroll(); }
  VR.scroll = false;
}
function vrScroll() { const el = $("#vu-refresh"); if (el) el.scrollIntoView({ block: "start", behavior: REDUCED ? "auto" : "smooth" }); }
async function startRefresh(focus, btn) {
  if (btn) btn.disabled = true;
  let r;
  try { r = await postJSON("/api/vulns/refresh", focus ? { focus } : {}); } catch (e) { r = { accepted: false, message: "Serveur injoignable." }; }
  r = r || {};
  if (r.status) VR.st = r;
  VR.msg = r.accepted ? "" : r.message || r.error || "La revérification n'a pas pu être lancée.";
  VR.msgT = Date.now() / 1000;
  VR.until = r.accepted ? 0 : r.retry_at || 0;
  if (r.accepted) { VR.hide = 0; VR.scroll = !!focus; }
  if (VR.until) setTimeout(() => { if (Date.now() / 1000 >= VR.until) { VR.msg = ""; VR.until = 0; if (CURRENT === "vulns") { renderVuRefresh(); renderVulns(false); } } }, Math.max(0, VR.until * 1000 - Date.now()) + 300);
  renderVuRefresh(); renderVulns(!r.accepted && !!focus && !r.retry_at && r.status !== "en_cours");   // action déjà résolue : liste rechargée
  if (btn && btn.isConnected) btn.disabled = vrBusy();
  if (focus) vrScroll();
  if (r.status === "en_cours") pollRefresh();
}
const vrBusy = () => vrState().status === "en_cours" || Date.now() / 1000 < VR.until;
const VR_VERDICT = {
  corrige: ["ok", "✓", "corrigé : n'apparaît plus dans l'analyse"],
  ameliore: ["ok", "↗", "amélioré"],
  aggrave: ["crit", "↘", "aggravé"],
  toujours: ["warn", "•", "toujours détecté"],
  incertain: ["warn", "?", "à confirmer"],
};
const vrHost = (h) => esc(HOST_LABEL[h] || h || "");
const vrUnit = (x) => (x.kind === "exposition" ? "constat(s)" : "CVE");
function vrChange(x) {
  const b = x.before || {}, parts = [];
  if (x.moved_from) return [b.version !== x.version && (b.version || x.version) ? `version ${esc(b.version || "?")} → ${esc(x.version || "?")}` : "", `désormais dans « ${esc(x.title)} »`].filter(Boolean).join(" · ");
  if (b.n !== x.n) parts.push(`${nf0.format(b.n || 0)} → ${nf0.format(x.n || 0)} ${vrUnit(x)}`);
  if (b.nc != null && x.nc != null && b.nc !== x.nc) parts.push(`${nf0.format(b.nc)} → ${nf0.format(x.nc)} composant(s) concerné(s)`);
  if (b.version !== x.version && (b.version || x.version)) parts.push(`version ${esc(b.version || "?")} → ${esc(x.version || "?")}`);
  if (b.priority !== x.priority) parts.push(`priorité ${esc(b.priority || "–")} → ${esc(x.priority || "–")}`);
  if (b.exposure && b.exposure !== x.exposure) parts.push(`exposition ${esc((EXPO[b.exposure] || EXPO.inconnue)[1])} → ${esc((EXPO[x.exposure] || EXPO.inconnue)[1])}`);
  if (!parts.length && b.score !== x.score) parts.push(`score de risque ${nf0.format(b.score || 0)} → ${nf0.format(x.score || 0)}`);
  return parts.join(" · ");
}
function vrFocus(f) {
  if (!f) return "";
  const v = VR_VERDICT[f.verdict] || ["mute", "•", "—"], b = f.before || {};
  const rest = f.n ? `encore ${nf0.format(f.n)} ${vrUnit(f)} à traiter` : "";
  let detail = "";
  if (f.verdict === "corrige") detail = "La correction est prise en compte.";
  else if (f.verdict === "incertain") detail = `L'action n'apparaît plus, mais ${esc(f.why || "l'analyse est incomplète")}. Relancez la vérification dans quelques minutes.`;
  else if (f.verdict === "ameliore" || f.verdict === "aggrave") detail = [vrChange(f), f.moved_from ? "" : rest].filter(Boolean).join(" · ");
  else if (f.kind === "exposition") detail = `Constat toujours présent${f.exposure_detail ? " : " + esc(f.exposure_detail) : ""}.`;
  else if (f.snapshot) detail = "Les conteneurs de clawhost sont lus dans sa sauvegarde de la nuit : la mise à jour apparaîtra après la prochaine sauvegarde.";
  else if (f.moved_from || (b.version && f.version && b.version !== f.version)) detail = `Mise à jour vue (${esc(b.version || "?")} → ${esc(f.version || "?")})${f.target ? `, mais la cible ${esc(f.target)} n'est pas encore atteinte` : ", mais le problème demeure"}${f.moved_from ? ` : l'action continue sous « ${esc(f.title)} »` : ""}.`;
  else detail = `Version vue : ${esc(f.version || "inconnue")}${f.target ? ` (cible ${esc(f.target)})` : ""} sur ${vrHost(f.host)}` +
    (f.reread === false ? ", d'après la dernière collecte réussie (relecture impossible)." : ", relue à l'instant.") +
    " Si le conteneur a été mis à jour, vérifiez qu'il a bien été recréé sur la nouvelle image ; un paquet ou un noyau peut demander un redémarrage.";
  return `<div class="vr-focus ${v[0]}"><span class="vr-ico">${v[1]}</span><div><b>${esc(f.moved_from && b.title ? b.title : f.title)}</b> — ${v[2]}<div class="cell-sub">${detail}</div></div></div>`;
}
function vrList(title, items, fmt) {
  return items && items.length ? `<div class="vr-group"><div class="lbl">${title} (${items.length})</div><ul>${items.slice(0, 12).map((x) => `<li>${fmt(x)}</li>`).join("")}${items.length > 12 ? `<li class="cell-sub">… et ${items.length - 12} autre(s)</li>` : ""}</ul></div>` : "";
}
const vrLine = (x) => `${esc(x.moved_from && x.before ? x.before.title : x.title)} <span class="cell-sub">${[vrHost(x.host), vrChange(x)].filter(Boolean).join(" · ")}</span>`;
function renderVuRefresh() {
  const el = $("#vu-refresh"); if (!el) return;
  const r = vrState(), V = VU.full || SL().vulns || {}, run = r.status === "en_cours", now = Date.now() / 1000;
  const gen = typeof V.generated_at === "number" ? V.generated_at : 0, inv = V.inventory_at || 0;
  if (VR.msg && VR.until && now >= VR.until) { VR.msg = ""; VR.until = 0; }
  if (VR.msg && !VR.until && !run && (/en cours/.test(VR.msg) || now - (VR.msgT || 0) > 60)) VR.msg = "";
  let html = `<div class="vr-bar"><div class="vr-info">${run
    ? `<span class="ai-spin"></span> <b>Revérification en cours</b>${r.phase === "attente" ? " — attente de la fin d'une analyse automatique" : ""} · depuis ${fmtDur(now - (r.started || now))}${r.expected_s ? ` (habituellement ~${fmtDur(r.expected_s)})` : ""}<div class="cell-sub">Relecture des versions installées (homelab, NAS ; clawhost par sondes réseau et sa sauvegarde nocturne), puis analyse OSV, GitHub, endoflife.date et CISA KEV.</div>`
    : `Scan ${gen ? fmtDate(gen) : "–"}${inv ? ` · inventaire ${fmtDate(inv)}` : ""}<div class="cell-sub">Automatique : inventaire toutes les heures (nouvelle analyse dès qu'une version, une exposition ou un constat change), analyse complète toutes les 12 h. Après une correction, revérifiez sans attendre.</div>`}</div>
    <button class="btn primary small" data-vrefresh ${vrBusy() ? "disabled" : ""}>${icon("refresh")}Revérifier maintenant</button></div>`;
  if (VR.msg) html += `<div class="hint vr-msg">${esc(VR.msg)}</div>`;
  const superseded = gen > (r.generated_at || 0) + 1 && now - (r.finished || 0) > 1800;   // une analyse plus récente l'a remplacé
  if (!run && (r.status === "ok" || r.status === "erreur") && r.finished && r.finished > VR.hide && !superseded) {
    const d = r.diff || {};
    if (r.status === "erreur") html += `<div class="vr-res crit"><button class="vr-x" data-vr-hide title="Masquer">×</button><b>Échec de la revérification</b> <span class="cell-sub">${fmtDate(r.finished)}</span><div class="cell-sub">${esc(r.error || "")}</div></div>`;
    else {
      const n = (k) => (d[k] || []).length, any = n("resolved") + n("improved") + n("added") + n("worse") + n("uncertain");
      html += `<div class="vr-res"><button class="vr-x" data-vr-hide title="Masquer">×</button>
        <div><b>Revérifié ${fmtDate(r.finished)}</b> <span class="cell-sub">en ${fmtDur(r.duration_s || 0)}</span> — ${any
          ? [[n("resolved"), "résolue(s)", "ok"], [n("improved"), "améliorée(s)", "ok"], [n("uncertain"), "à confirmer", "warn"], [n("worse"), "aggravée(s)", "crit"], [n("added"), "nouvelle(s)", "warn"]].filter((x) => x[0]).map((x) => `<span class="tag ${x[2]}">${x[0]} ${x[1]}</span>`).join(" ")
          : d.after === 1 ? "aucun changement : l'action restante est toujours d'actualité." : `aucun changement : les ${nf0.format(d.after || 0)} actions sont toujours d'actualité.`}${d.partial ? ' <span class="tag warn" title="Une source était injoignable : certaines vulnérabilités peuvent manquer">analyse incomplète</span>' : ""}</div>
        ${vrFocus(d.focus)}
        ${vrList("Résolues", d.resolved, (x) => `<span class="vr-ok">✓</span> ${esc(x.title)} <span class="cell-sub">${vrHost(x.host)}</span>`)}
        ${vrList("Améliorées", d.improved, vrLine)}
        ${vrList("À confirmer", d.uncertain, (x) => `${esc(x.title)} <span class="cell-sub">${vrHost(x.host)} · ${esc(x.why || "")}</span>`)}
        ${vrList("Aggravées", d.worse, vrLine)}
        ${vrList("Nouvelles", d.added, (x) => `${esc(x.title)} <span class="cell-sub">${vrHost(x.host)} · priorité ${esc(x.priority || "–")}</span>`)}</div>`;
    }
  }
  setHTML(el, html);
  if (run && !VR.polling) pollRefresh();
}
function renderVulns(first) {
  if (!$("#vu-host").dataset.init) {
    $("#vu-host").dataset.init = 1;
    segment($("#vu-host"), (b) => { VU.host = b.dataset.h; renderVulns(false); });
    segment($("#vu-prio"), (b) => { VU.prio = b.dataset.p; renderVulns(false); });
    $("#vu-search").addEventListener("input", () => renderVulns(false));
    $("#vu-inv-search").addEventListener("input", () => renderVulns(false));
    $("#v-vulns").addEventListener("click", (e) => {
      const c = e.target.closest("[data-copy]");
      if (c) { copyFromBtn(c); return; }
      const rf = e.target.closest("[data-vrefresh],[data-recheck]");
      if (rf) { startRefresh(rf.dataset.recheck || null, rf); return; }
      if (e.target.closest("[data-vr-hide]")) {
        VR.hide = vrState().finished || Date.now() / 1000; if (!VR.until) VR.msg = "";
        try { localStorage.setItem("infradash.vr-hide", String(VR.hide)); } catch (err) { /* stockage indisponible */ }
        renderVuRefresh(); return;
      }
      const t = e.target.closest("[data-toggle]");
      if (t) { const id = t.dataset.toggle; VU.open.has(id) ? VU.open.delete(id) : VU.open.add(id); renderVulns(false); }
    });
  }
  loadVulns(first);
  renderVuRefresh();
  const sum = SL().vulns || {}, V = VU.full || sum;
  const st = V.stats || {}, bp = st.by_priority || {};
  const actions = V.actions || [], findings = (VU.full && VU.full.findings) || [], inv = (VU.full && VU.full.inventory) || [];
  if (!V.generated_at && !actions.length) {
    setHTML($("#vu-kpis"), `<div class="card kpi"><div class="lbl">Vulnérabilités</div><div class="val">…</div><div class="foot">premier scan en cours (OSV, GitHub, endoflife.date, CISA KEV, EPSS)</div></div>`);
    setHTML($("#vu-plan"), '<div class="empty">Analyse en cours : le premier scan complet prend 1 à 3 minutes.</div>');
    return;
  }
  const kev = findings.length ? findings.filter((f) => f.kev).length : actions.filter((a) => a.kev).length;
  const inet = actions.filter((a) => a.exposure === "internet").length;
  setHTML($("#vu-kpis"), [
    ["Composants suivis", nf0.format(st.total_components || V.n_inventory || inv.length || 0), `${nf0.format(st.scanned_components || 0)} versions identifiées`, "var(--blue)"],
    ["Vulnérabilités", nf0.format(st.findings ?? V.n_findings ?? findings.length), `corrélées à vos versions · ${nf0.format(st.nofix_distro || 0)} sans correctif distribution écartées`, "var(--violet)"],
    ["Critiques", nf0.format(bp.critique || 0), `${nf0.format(bp.haute || 0)} hautes · ${nf0.format(bp.moyenne || 0)} moyennes`, bp.critique ? "var(--crit)" : "var(--ok)"],
    ["Exploitées (KEV)", nf0.format(kev), "catalogue CISA des failles activement exploitées", kev ? "var(--crit)" : "var(--ok)"],
    ["Actions", nf0.format(actions.length), `${inet} touchent un service exposé sur Internet`, "var(--amber)"],
    ["Fins de vie", nf0.format(st.eol ?? (V.eol || []).filter((e) => e.status === "fin de vie").length), `+ ${nf0.format(st.outdated || 0)} composants en retard de correctif`, st.eol ? "var(--warn)" : "var(--ok)"],
  ].map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
  $("#vu-plan-sub").textContent = `${actions.length} actions, triées par risque réel (gravité × exposition × exploitation)`;
  const vr = vrState(), busy = vrBusy();
  setHTML($("#vu-plan"), actions.slice(0, 40).map((a, i) => {
    const id = "a" + (a.component_id || i), open = VU.open.has(id);
    const cids = new Set(a.component_ids || [a.component_id]);
    const fs = open ? findings.filter((f) => (a.findings || []).includes(f.id) && cids.has(f.component_id)) : [];
    return `<div class="vuln-action ${(PRIO[a.priority] || ["mute"])[0]}">
      <div class="vuln-head"><span class="vuln-score" title="Score de risque">${nf0.format(a.max_score || 0)}</span>
        <div class="vuln-title"><b>${esc(a.title || a.component)}</b><div class="cell-sub">${esc(HOST_LABEL[a.host] || a.host)}${a.container ? " · " + esc(a.container) : ""} · ${esc(a.component)} ${esc(a.version || "")}${a.target_version ? " → <b>" + esc(a.target_version) + "</b>" : ""}</div></div>
        <div class="vuln-tags">${prioTag(a.priority)}${expoTag(a.exposure)}${a.kev ? '<span class="tag crit" title="Faille activement exploitée (CISA KEV)">KEV</span>' : ""}<span class="tag mute">${a.n_findings || 0} CVE</span></div></div>
      ${a.remediation ? `<p class="vuln-rem">${esc(a.remediation)}</p>` : ""}
      ${(a.commands || []).length ? `<div class="vuln-cmd"><pre>${esc(a.commands.join("\n"))}</pre>${copyBtn(a.commands.join("\n"))}</div>` : ""}
      <div class="vuln-btns">${(a.findings || []).length ? `<button class="btn ghost small" data-toggle="${esc(id)}">${open ? "Masquer" : "Voir"} les ${a.findings.length} vulnérabilités</button>` : ""}${a.id ? `<button class="btn ghost small" data-recheck="${esc(a.id)}" ${busy ? "disabled" : ""} title="Après avoir appliqué la correction : relit les versions installées et refait l'analyse">${icon("refresh")}Revérifier</button>` : ""}${vr.status === "en_cours" && vr.focus === a.id ? '<span class="cell-sub vr-inline"><span class="ai-spin"></span> revérification en cours, le bilan s\'affichera en haut du plan</span>' : ""}</div>
      ${open ? `<div class="vuln-flist">${fs.length < (a.findings || []).length && fs.length ? `<div class="hint">${(a.findings || []).length - fs.length} autres constats non détaillés ici (liste tronquée côté serveur).</div>` : ""}${(fs.length ? fs : (a.findings || []).map((x) => ({ id: x }))).map((f) => `<div class="vuln-f"><a class="mono" href="${esc((f.refs || [])[0] || "https://osv.dev/vulnerability/" + f.id)}" target="_blank" rel="noopener">${esc(f.id)}</a>${f.cvss ? ` <span class="tag">${nf1.format(f.cvss)}</span>` : ""}${f.kev ? ' <span class="tag crit">KEV</span>' : ""}${f.epss != null ? ` <span class="cell-sub">EPSS ${nf1.format(f.epss * 100)} %</span>` : ""}<div class="cell-sub">${esc((f.title || f.summary || "").slice(0, 220))}</div></div>`).join("")}</div>` : ""}
    </div>`; }).join("") || '<div class="empty">Aucune action nécessaire 🎉</div>');
  const dg = (SL().netscan || {}).digest;
  $("#vu-lan-card").hidden = !dg;
  setHTML($("#vu-lan"), dg ? `<div class="cell-sub">${(dg.active || []).length ? `${dg.active.length} appareil(s) à vérifier (présents sur le réseau, hors machines suivies ci-contre) :` : `Aucune vulnérabilité retenue hors des machines suivies ci-contre.`}</div>
    ${(dg.active || []).map((g) => `<div class="vr-focus ${g.precise ? "crit" : "warn"}"><span class="vr-ico">${g.precise ? "!" : "?"}</span><div><b>${esc(g.device)}</b> <span class="cell-sub">${esc(g.ip)}</span> — ${esc(g.product)} ${esc(g.version)}, ${nf0.format(g.n)} CVE (CVSS max ${nf1.format(g.max_cvss)})<div class="cell-sub">${esc(g.why || "Mettre à jour l'appareil, ou l'isoler du LAN s'il n'a plus de mises à jour.")} · ${g.cves.slice(0, 4).map((c) => `<a class="mono" href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener">${esc(c)}</a>`).join(", ")}</div></div></div>`).join("")}
    ${(dg.dropped || []).length ? `<div class="vr-group"><div class="lbl">Écartées (${nf0.format(dg.n_cve_dropped)} CVE)</div><ul>${dg.dropped.map((g) => `<li><b>${esc(g.device)}</b> <span class="cell-sub">${esc(g.ip || "")}</span> — ${esc(g.product)} ${esc(g.version)} : ${nf0.format(g.n)} CVE · <span class="cell-sub">${esc(g.why)}</span></li>`).join("")}</ul></div>` : ""}` : "");
  // Graphe : priorités par hôte
  const hosts = ["homelab", "nas", "clawhost"], prios = ["critique", "haute", "moyenne", "basse"];
  const cnt = (h, p) => ((st.by_host || {})[h] || {})[p] ?? actions.filter((a) => a.host === h && a.priority === p).reduce((s, a) => s + (a.n_findings || 0), 0);
  const colors = { critique: "#FF453A", haute: "#FF9F0A", moyenne: "#4A9EFF", basse: "#636366" };
  const ch = chart($("#vu-chart"));
  ch && ch.setOption(baseOpt({ grid: { left: 70, right: 16, top: 28, bottom: 24 }, tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    xAxis: { type: "log", min: 1, ...AX }, yAxis: { type: "category", data: hosts.map((h) => HOST_LABEL[h]), ...AX },
    series: prios.map((p) => ({ name: p, type: "bar", barGap: "10%", barWidth: 7, itemStyle: { color: colors[p], borderRadius: 2 }, data: hosts.map((h) => cnt(h, p) || null) })) }), true);
  const eolSorted = (V.eol || []).slice().sort((a, b) => (a.status === "fin de vie" ? 0 : 1) - (b.status === "fin de vie" ? 0 : 1));
  setHTML($("#vu-eol"), eolSorted.length ? `<div class="tbl-wrap scroll" style="max-height:420px"><table><tr><th>Composant</th><th>Hôte</th><th>Installée</th><th>Statut</th><th>Cible</th></tr>${eolSorted.map((e) =>
    `<tr><td><b>${esc(e.component)}</b>${e.container ? `<div class="cell-sub">${esc(e.container)}</div>` : ""}</td><td>${esc(HOST_LABEL[e.host] || e.host || "")}</td><td class="mono">${esc(e.version || e.cycle || "")}</td>
     <td>${e.status === "fin de vie" ? `<span class="tag crit">fin de vie</span><div class="cell-sub">depuis ${nf0.format(e.days_past || 0)} j</div>` : `<span class="tag warn">${esc(e.status || "")}</span>${e.behind ? `<div class="cell-sub">${nf0.format(e.behind)} version(s) de retard</div>` : ""}`}</td>
     <td class="mono cell-sub">${esc(e.status === "fin de vie" ? (e.next_cycle || e.best_cycle || "") : (e.latest || ""))}</td></tr>`).join("")}</table></div>` : '<div class="empty">Aucune</div>');
  $("#vu-gen").textContent = V.generated_at ? "scan " + ago(typeof V.generated_at === "number" ? V.generated_at : Date.parse(V.generated_at) / 1000) + (V.inventory_at ? " · inventaire " + ago(V.inventory_at) : "") : "";
  setHTML($("#vu-sources"), `<table>${Object.entries(V.sources || {}).map(([k, s]) => `<tr><td>${esc(k)}</td><td><span class="tag ${s.ok ? "ok" : "crit"}">${s.ok ? "ok" : "erreur"}</span>${s.error ? `<div class="cell-sub">${esc(String(s.error).slice(0, 120))}</div>` : ""}</td><td class="num">${s.n != null ? nf0.format(s.n) : ""}</td></tr>`).join("")}</table>
    <div class="hint mt">Seuls des noms de logiciels et numéros de version sont envoyés à OSV.dev, GitHub, endoflife.date et FIRST (EPSS), et des noms d'images aux registres (Docker Hub, ghcr.io…) pour vérifier qu'un pull apporte bien le correctif — aucune adresse ni donnée de configuration.</div>`);
  const q = $("#vu-search").value.toLowerCase();
  const fl = findings.filter((f) => (VU.host === "all" || f.host === VU.host) && (VU.prio === "all" || f.priority === VU.prio) &&
    (!q || [f.id, (f.aliases || []).join(" "), f.component, f.container, f.title, f.summary].join(" ").toLowerCase().includes(q)));
  $("#vu-count").textContent = findings.length ? `${fl.length} / ${findings.length}` : "chargement…";
  setHTML($("#vu-table"), `<tr><th>Vulnérabilité</th><th>Composant</th><th>Hôte</th><th class="num">CVSS</th><th class="num">EPSS</th><th>Exposition</th><th>Priorité</th><th>Correctif</th></tr>` +
    fl.slice(0, 300).map((f) => `<tr><td><a class="mono" href="${esc((f.refs || [])[0] || "https://osv.dev/vulnerability/" + f.id)}" target="_blank" rel="noopener">${esc(f.id)}</a>${f.kev ? ' <span class="tag crit">KEV</span>' : ""}<div class="cell-sub">${esc((f.title || f.summary || "").slice(0, 140))}</div></td>
      <td>${esc(f.component)} <span class="mono cell-sub">${esc(f.version || "")}</span>${f.container ? `<div class="cell-sub">${esc(f.container)}</div>` : ""}</td><td>${esc(HOST_LABEL[f.host] || f.host)}</td>
      <td class="num">${f.cvss != null ? nf1.format(f.cvss) : esc(f.severity || "–")}</td><td class="num">${f.epss != null ? nf1.format(f.epss * 100) + " %" : "–"}</td>
      <td>${expoTag(f.exposure)}</td><td>${prioTag(f.priority)}</td><td class="mono cell-sub">${f.nofix ? "aucun" : esc(f.fixed || "–")}</td></tr>`).join("") +
    (fl.length > 300 ? `<tr><td colspan="8" class="empty">${fl.length - 300} lignes de plus : affinez le filtre</td></tr>` : ""));
  const qi = $("#vu-inv-search").value.toLowerCase();
  const il = inv.filter((c) => !qi || [c.name, c.version, c.host, c.container, c.kind].join(" ").toLowerCase().includes(qi));
  $("#vu-inv-sub").textContent = inv.length ? `${inv.length} composants · paquets Debian du homelab inclus` : "";
  setHTML($("#vu-inv"), `<tr><th>Composant</th><th>Version</th><th>Type</th><th>Hôte</th><th>Exposition</th><th>Détection</th></tr>` + il.slice(0, 400).map((c) =>
    `<tr><td><b>${esc(c.name)}</b>${c.container ? `<div class="cell-sub">${esc(c.container)}</div>` : ""}</td><td class="mono">${esc(c.version || "inconnue")}</td><td class="cell-sub">${esc(c.kind || "")}</td><td>${esc(HOST_LABEL[c.host] || c.host)}</td><td>${expoTag(c.exposure)}</td><td class="cell-sub">${esc(c.source || "")}</td></tr>`).join("") +
    (il.length > 400 ? `<tr><td colspan="6" class="empty">${il.length - 400} de plus : affinez le filtre</td></tr>` : ""));
}

/* ===================================================================== NOTES & ALERTES */
const GRADE_CLS = { A: "ok", B: "ok", C: "warn", D: "warn", E: "crit", F: "crit" };
const CAT_ICON = { sante: "cpu", securite: "bug", resilience: "backup", maintenance: "cal", confidentialite: "map" };
function scoreRing(score, size, grade) {
  const r = size / 2 - 5, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, score || 0));
  const col = v >= 80 ? "var(--ok)" : v >= 60 ? "var(--warn)" : "var(--crit)";
  return `<svg class="sc-ring" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--track)" stroke-width="5"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${col}" stroke-width="5" stroke-linecap="round" stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - v / 100)}" transform="rotate(-90 ${size / 2} ${size / 2})" class="sc-arc"/>
    <text x="50%" y="50%" text-anchor="middle" dominant-baseline="central" class="sc-num" style="font-size:${size * 0.3}px">${grade || nf0.format(v)}</text></svg>`;
}
function renderScoreStrip() {
  const sc = D().scores; const el = $("#ov-scores"); if (!el) return;
  if (!sc || !sc.global) { setHTML(el, ""); return; }
  setHTML(el, `<a class="card score-main" href="#scores">${scoreRing(sc.global.score, 74, sc.global.grade)}<div><div class="lbl">Note globale</div><div class="val">${nf0.format(sc.global.score)}<small>/100</small></div><div class="foot">${esc(sc.global.label || "")}</div></div></a>` +
    (sc.categories || []).map((c) => `<a class="card score-cat" href="#scores">${scoreRing(c.score, 46, c.grade)}<div><div class="lbl">${esc(c.label)}</div><div class="val sm">${nf0.format(c.score)}</div></div></a>`).join(""));
}
/* Axes d'amélioration : action exécutée par le dashboard quand c'est sûr (diagnostic en lecture seule, pause de parité),
   sinon mode opératoire pas à pas. Le catalogue et les résultats viennent du serveur (infradash/actions.py). */
const ACT = { busy: null, res: {}, open: new Set() };
function axesShown(ax) {
  const AC = D().actions || {}, has = (a) => !!(AC.modops || {})[a.id] || Object.values(AC.actions || {}).some((x) => (x.for || []).includes(a.id));
  return ax.slice(0, 14).concat(ax.slice(14).filter(has));   // au-delà des 14 premiers : seulement ceux qu'on peut traiter d'ici
}
function actResult(id, title) {
  const AC = D().actions || {}, r = (ACT.res[id] && (ACT.res[id].t || 0) >= (((AC.results || {})[id] || {}).t || 0)) ? ACT.res[id] : (AC.results || {})[id];
  if (!r) return "";
  const lv = r.ok ? r.level || "ok" : "crit";
  let body = "";
  if ((r.table || []).length) body = `<div class="tbl-wrap"><table><tr><th>Disque</th><th>État SMART</th><th class="num">°C</th><th>Constats</th></tr>${r.table.map((d) => `<tr><td><b>${esc(d.disk)}</b> <span class="cell-sub mono">${esc(d.dev)}</span></td><td><span class="tag ${d.level === "crit" ? "crit" : d.level === "warn" ? "warn" : "ok"}">${esc(d.health || "?")}</span></td><td class="num">${d.temp != null ? nf0.format(d.temp) : "–"}</td><td class="cell-sub">${esc((d.issues || []).join(" · ") || "aucun")}${d.wear ? ` · usure ${esc(d.wear)}` : ""}</td></tr>`).join("")}</table></div>`;
  if ((r.lines || []).length) body += `<pre class="act-pre">${esc(r.lines.join("\n"))}</pre>`;
  if ((r.kv || []).length) body += `<div class="cell-sub mono">${r.kv.map(([k, v]) => `${esc(k)} = ${esc(v)}`).join(" · ")}</div>`;
  return `<div class="act-res ${lv}"><b>${esc(title)}</b> <span class="cell-sub">${fmtDate(r.t)}${r.duration_s != null ? ` · ${nf1.format(r.duration_s)} s` : ""}</span><div>${esc(r.ok ? r.summary || "" : "Échec : " + (r.error || ""))}</div>${body}</div>`;
}
function axeDo(a) {
  const AC = D().actions || {}, acts = Object.values(AC.actions || {}).filter((x) => (x.for || []).includes(a.id)), mo = (AC.modops || {})[a.id];
  if (!acts.length && !mo) return "";
  const busy = ACT.busy || AC.running;
  const btns = acts.filter((x) => x.available).map((x) => `<button class="btn small ${x.kind === "change" ? "primary" : "ghost"}" data-act="${esc(x.id)}" ${busy ? "disabled" : ""} title="${esc(x.about || "")}">${ACT.busy === x.id ? '<span class="ai-spin"></span>' : icon(x.kind === "change" ? "refresh" : "info")}${esc(x.title)}</button>`).join("");
  const res = acts.map((x) => actResult(x.id, x.title)).join("");
  const steps = mo ? `<details class="modop" data-mo="${esc(a.id)}" ${ACT.open.has(a.id) ? "open" : ""}><summary>Mode opératoire · ${mo.steps.length} étapes</summary>${mo.why ? `<p class="cell-sub">${esc(mo.why)}</p>` : ""}<ol>${mo.steps.map((st) => `<li>${esc(st[0])}${st[1] ? `<div class="vuln-cmd"><pre>${esc(st[1])}</pre>${copyBtn(st[1])}</div>` : ""}</li>`).join("")}</ol>${mo.verify ? `<div class="hint"><b>Vérifier :</b> ${esc(mo.verify)}</div>` : ""}</details>` : "";
  const par = (AC.parity || {}).state && acts.some((x) => x.id.startsWith("parity-")) ? `<span class="cell-sub">Contrôle de parité : ${esc({ en_cours: "en cours", en_pause: "en pause", aucun: "aucun" }[AC.parity.state] || AC.parity.state)}${AC.parity.pct != null ? ` (${nf1.format(AC.parity.pct)} %)` : ""}</span>` : "";
  return `<div class="axe-do">${btns || par ? `<div class="row-flex wrap">${btns}${par}</div>` : ""}${res}${steps}</div>`;
}
async function runAction(id) {
  const x = ((D().actions || {}).actions || {})[id];
  if (!x) return;
  if (x.kind === "change" && !window.confirm(x.confirm || `${x.title} ?`)) return;
  ACT.busy = id; renderScores();
  let r;
  try { r = await postJSON("/api/actions/run", { id }); } catch (e) { r = { ok: false, error: "Serveur injoignable.", t: Date.now() / 1000 }; }
  ACT.res[id] = Object.assign({ t: Date.now() / 1000 }, r || {});
  ACT.busy = null; renderScores();
}

function renderScores(first) {
  if (!$("#sc-axes").dataset.init) {
    $("#sc-axes").dataset.init = 1;
    $("#sc-axes").addEventListener("click", (e) => { const b = e.target.closest("[data-act]"); if (b) runAction(b.dataset.act); });
    $("#sc-axes").addEventListener("toggle", (e) => { const d = e.target.closest && e.target.closest("[data-mo]"); if (d) d.open ? ACT.open.add(d.dataset.mo) : ACT.open.delete(d.dataset.mo); }, true);
  }
  const sc = D().scores || {};
  $("#sc-sub").textContent = sc.global ? `${nf0.format(sc.global.score)}/100 · ${sc.global.grade}` : "calcul en cours…";
  setHTML($("#sc-cats"), sc.global ? `<div class="sc-hero">${scoreRing(sc.global.score, 120, sc.global.grade)}<div><div class="sc-big">${nf0.format(sc.global.score)}<small>/100</small></div><div class="hint">${esc(sc.global.label || "")}</div></div></div>
    <div class="sc-grid">${(sc.categories || []).map((c) => `<div class="sc-cat">${scoreRing(c.score, 56, c.grade)}<div><b>${esc(c.label)}</b> <span class="mono cell-sub">${nf0.format(c.score)}/100</span><div class="cell-sub">${esc(c.summary || "")}</div></div></div>`).join("")}</div>` : '<div class="empty">Calcul en cours…</div>');
  const h = sc.history || [];
  const cc = chart($("#sc-hist"));
  const cols = { global: "#ffffff", sante: "#30D158", securite: "#FF453A", resilience: "#4A9EFF", maintenance: "#FF9F0A", confidentialite: "#BF5AF2" };
  const names = { global: "Globale", sante: "Santé", securite: "Sécurité", resilience: "Résilience", maintenance: "Maintenance", confidentialite: "Confidentialité" };
  cc && cc.setOption(baseOpt({ xAxis: { type: "category", data: h.map((x) => x.date), ...AX }, yAxis: { type: "value", min: 0, max: 100, ...AX },
    series: Object.keys(cols).map((k) => lineSeries(names[k], h.map((x) => x[k]), cols[k], false, { showSymbol: h.length < 3, symbolSize: 6, lineStyle: { width: k === "global" ? 2.5 : 1.5, color: cols[k] } })) }), true);
  const axList = axesShown(sc.axes || []);
  setHTML($("#sc-axes"), axList.map((a, i) => `<div class="axe"><span class="axe-n">${i + 1}</span><div class="axe-body"><div class="row-flex"><b>${esc(a.title)}</b>
      <span class="tag ok" style="margin-left:auto" title="Points regagnés sur la note globale">+${nf1.format(a.gain || 0)} pts</span><span class="tag mute">effort ${esc(a.effort || "?")}</span></div>
      ${a.detail ? `<div class="cell-sub">${esc(a.detail)}</div>` : ""}${a.action ? `<div class="act">${esc(a.action)}</div>` : ""}<div class="tags"><span class="tag">${esc(a.category || "")}</span></div>${axeDo(a)}</div></div>`).join("") || '<div class="empty">Rien à améliorer pour l\'instant</div>');
  setHTML($("#sc-detail"), (sc.categories || []).map((c) => `<div class="sc-det"><div class="row-flex">${icon(CAT_ICON[c.id] || "info")}<b>${esc(c.label)}</b><span class="tag ${GRADE_CLS[c.grade] || "mute"}" style="margin-left:auto">${esc(c.grade)} · ${nf0.format(c.score)}</span></div>
    ${(c.items || []).length ? `<ul class="sc-items">${c.items.map((it) => `<li><span class="mono pen">−${nf1.format(it.penalty || 0)}</span><div><b>${esc(it.label)}</b>${it.detail ? `<div class="cell-sub">${esc(it.detail)}</div>` : ""}${it.fix ? `<div class="act">${esc(it.fix)}</div>` : ""}</div></li>`).join("")}</ul>` : '<div class="hint mt">Aucune pénalité 👌</div>'}</div>`).join(""));
  renderAlertsFull();
}
async function postJSON(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-InfraDash": "1" }, body: JSON.stringify(body || {}) });
  return r.json();
}
function alertRow(a, compact) {
  return `<div class="al ${a.level} ${a.acked ? "acked" : ""}"><span class="dot ${a.level === "crit" ? "crit" : "warn"}"></span><div class="al-body"><b>${esc(a.title)}</b>
    <div class="cell-sub">${esc(HOST_LABEL[a.host] || a.host || "")} · ${esc(a.source || "")} · depuis ${fmtDate(a.first_seen)}</div>${!compact && a.detail ? `<div class="cell-sub">${esc(a.detail).slice(0, 400)}</div>` : ""}${!compact && a.action ? `<div class="act">${esc(a.action)}</div>` : ""}</div>
    <button class="btn ghost small" data-ack="${esc(a.key)}" ${a.acked ? 'data-undo="1"' : ""}>${a.acked ? "Rouvrir" : "Acquitter"}</button></div>`;
}
function bindAlertClicks(el) {
  if (el.dataset.bound) return; el.dataset.bound = 1;
  el.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-ack]"); const all = e.target.closest("[data-ack-all]");
    if (!b && !all) return;
    e.stopPropagation();
    try { const r = await postJSON("/api/alerts/ack", all ? { all: true } : { key: b.dataset.ack, undo: !!b.dataset.undo }); S.derived = S.derived || {}; S.derived.alerts = r; } catch (err) { /* état suivant via le flux */ }
    renderBell(); if (CURRENT === "scores") renderAlertsFull();
  });
}
function renderAlertsFull() {
  const al = D().alerts || {}, act = al.active || [];
  setHTML($("#al-actions"), act.some((a) => !a.acked) ? '<button class="btn ghost small" data-ack-all="1">Tout acquitter</button>' : "");
  setHTML($("#al-list"), (act.length ? act.map((a) => alertRow(a)).join("") : '<div class="empty">Aucune alerte active 🎉</div>') +
    ((al.resolved || []).length ? `<h3 class="mt">Résolues récemment</h3>${al.resolved.slice(0, 8).map((a) => `<div class="al resolved"><span class="dot ok"></span><div class="al-body"><b>${esc(a.title)}</b><div class="cell-sub">résolue ${fmtDate(a.resolved_t || a.last_seen)}</div></div></div>`).join("")}` : ""));
  bindAlertClicks($("#al-list")); bindAlertClicks($("#al-actions"));
  const n = al.notify || {};
  const box = $("#al-notify");
  setHTML(box, `<label class="switch"><input type="checkbox" id="nt-unraid" ${n.enabled ? "checked" : ""}><span></span>Envoyer les nouvelles alertes critiques aux notifications Unraid</label>
    <label class="switch"><input type="checkbox" id="nt-warn" ${n.notify_warn ? "checked" : ""}><span></span>Inclure aussi les alertes « attention »</label>
    <div class="hint mt">Unraid relaie ensuite vers les canaux que tu y as configurés (mail, Telegram, Pushover…) : Settings → Notification Settings. C'est la seule écriture que le dashboard fait sur le NAS, et seulement si tu l'actives. Maximum 10 envois par 24 h.${n.last_sent ? ` Dernier envoi : ${fmtDate(n.last_sent)}.` : ""}</div>`);
  if (!box.dataset.bound) {
    box.dataset.bound = 1;
    box.addEventListener("change", async () => {
      try { await postJSON("/api/settings", { notify_unraid: $("#nt-unraid").checked, notify_warn: $("#nt-warn").checked }); } catch (e) { /* ignoré */ }
    });
  }
}
function renderBell() {
  const al = D().alerts || {}, act = (al.active || []).filter((a) => !a.acked);
  const crit = act.filter((a) => a.level === "crit").length;
  const b = $("#alert-bell"); if (!b) return;
  $("#alert-count").textContent = act.length;
  b.classList.toggle("has-crit", crit > 0); b.classList.toggle("has-warn", !crit && act.length > 0);
  const p = $("#alert-panel");
  if (!p.hidden) setHTML(p, `<div class="row-flex"><b>Alertes actives</b><a class="r" href="#scores" style="margin-left:auto">tout voir →</a></div>${act.slice(0, 8).map((a) => alertRow(a, true)).join("") || '<div class="empty">Aucune alerte non acquittée</div>'}`);
  if (!b.dataset.bound) {
    b.dataset.bound = 1; bindAlertClicks(p);
    b.addEventListener("click", (e) => { e.stopPropagation(); p.hidden = !p.hidden; renderBell(); });
    document.addEventListener("click", (e) => { if (!p.hidden && !p.contains(e.target)) p.hidden = true; });
  }
}

/* ===================================================================== FLUX SORTANTS */
const RISK = { eleve: ["crit", "élevé"], moyen: ["warn", "moyen"], faible: ["ok", "faible"] };
const EG = { risk: "all", open: new Set() };
function renderEgress(first) {
  const eg = SL().egress || {};
  if (!$("#eg-risk").dataset.init) {
    $("#eg-risk").dataset.init = 1;
    segment($("#eg-risk"), (b) => { EG.risk = b.dataset.r; renderEgress(true); if (WORLD && WORLD.setFilter) WORLD.setFilter({ risk: EG.risk === "all" ? null : EG.risk }); });
    $("#eg-search").addEventListener("input", () => renderEgress(true));
    $("#v-egress").addEventListener("click", (e) => {
      const c = e.target.closest("[data-copy]");
      if (c) { copyFromBtn(c); return; }
      const t = e.target.closest("[data-eg]");
      if (t) { const id = t.dataset.eg; EG.open.has(id) ? EG.open.delete(id) : EG.open.add(id); renderEgress(true); }
    });
  }
  if (window.WorldMap && !WORLD) WORLD = new WorldMap($("#eg-map"), { onSelect: (d) => { $("#eg-search").value = d.ip; EG.open.add(d.ip); renderEgress(true); } });
  if (WORLD && eg.destinations) WORLD.setData(eg);
  const st = eg.stats || {}, ds = eg.destinations || [];
  if (!eg.generated_at) { setHTML($("#eg-kpis"), '<div class="card kpi"><div class="lbl">Flux sortants</div><div class="val">…</div><div class="foot">première collecte en cours</div></div>'); return; }
  setHTML($("#eg-kpis"), [
    ["Destinations", nf0.format(st.n_dest ?? ds.length), "serveurs Internet contactés", "var(--blue)"],
    ["Pays", nf0.format(st.n_countries ?? (eg.countries || []).length), `${nf0.format(st.n_outside_eu || 0)} destinations hors UE`, "var(--violet)"],
    ["Risque élevé", nf0.format(ds.filter((d) => d.risk === "eleve").length), "à examiner en priorité", ds.some((d) => d.risk === "eleve") ? "var(--crit)" : "var(--ok)"],
    ["Nouvelles", nf0.format(ds.filter((d) => d.is_new).length), "jamais vues avant", "var(--amber)"],
    ["Sources", nf0.format((eg.by_source || []).length), "hôtes, VM et conteneurs qui sortent", "var(--teal)"],
  ].map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
  const q = $("#eg-search").value.toLowerCase();
  const fl = ds.filter((d) => (EG.risk === "all" || d.risk === EG.risk) && (!q || [d.ip, d.ptr, d.org, d.service, d.country_name, d.category, (d.sources || []).map((s) => s.name).join(" ")].join(" ").toLowerCase().includes(q)))
    .sort((a, b) => ({ eleve: 0, moyen: 1, faible: 2 }[a.risk] ?? 3) - ({ eleve: 0, moyen: 1, faible: 2 }[b.risk] ?? 3) || (b.conns || 0) - (a.conns || 0));
  $("#eg-sub").textContent = `${fl.length} / ${ds.length}`;
  setHTML($("#eg-table"), `<tr><th>Service</th><th>Pays</th><th>Adresse</th><th>Depuis</th><th class="num">Conn.</th><th>Risque</th><th></th></tr>` + fl.map((d) => {
    const open = EG.open.has(d.ip), r = RISK[d.risk] || ["mute", d.risk || "?"];
    return `<tr><td><b>${esc(d.service || d.org || "inconnu")}</b><div class="cell-sub">${esc(d.category || "")}${d.org && d.service !== d.org ? " · " + esc(d.org) : ""}${d.asn ? " · AS" + esc(d.asn) : ""}</div></td>
      <td>${esc(d.country_name || d.country || "?")}${d.region ? `<div class="cell-sub">${esc(d.region)}</div>` : ""}${d.eu === false ? ' <span class="tag mute">hors UE</span>' : ""}</td>
      <td class="mono">${esc(d.ip)}<div class="cell-sub">${esc(d.ptr || "")} ${esc((d.ports || []).map((p) => (d.protos || [])[0] ? p : p).join(", "))}</div></td>
      <td>${(d.sources || []).slice(0, 3).map((s) => `<span class="tag">${esc(s.name || s.src_ip)}</span>`).join(" ")}</td>
      <td class="num">${nf0.format(d.conns || 0)}${d.is_new ? ' <span class="tag warn">nouveau</span>' : ""}</td><td><span class="tag ${r[0]}">${esc(r[1])}</span></td>
      <td><button class="btn ghost small" data-eg="${esc(d.ip)}">${open ? "Fermer" : "Bloquer…"}</button></td></tr>
      ${open ? `<tr class="eg-detail"><td colspan="7"><div class="cell-sub">${esc(d.why || "")} · vu de ${fmtDate(d.first_seen)} à ${fmtDate(d.last_seen)}</div>${(d.block || []).map((b) => `<div class="eg-block"><span class="tag info">${esc(b.method)}</span> ${esc(b.how)}${b.impact ? `<div class="eg-impact"><b>Conséquence :</b> ${esc(b.impact)}</div>` : ""}${b.rule ? `<div class="vuln-cmd"><pre>${esc(b.rule)}</pre>${copyBtn(b.rule)}</div>` : ""}</div>`).join("")}</td></tr>` : ""}`;
  }).join(""));
  setHTML($("#eg-findings"), (eg.findings || []).map((f) => insightHTML({ level: f.level, title: f.title, detail: f.detail, action: f.action, host: "", tag: "confidentialité" })).join("") || '<div class="empty">Rien de notable</div>');
  setHTML($("#eg-sources"), `<tr><th>Source</th><th>Type</th><th class="num">Destinations</th><th>Pays</th></tr>` + (eg.by_source || []).map((s) =>
    `<tr><td><b>${esc(s.name)}</b><div class="cell-sub">${esc(HOST_LABEL[s.host] || s.host || "")}</div></td><td class="cell-sub">${esc(s.kind || "")}</td><td class="num">${nf0.format(s.n_dest || 0)}</td><td class="cell-sub">${esc((s.countries || []).join(", "))}</td></tr>`).join(""));
  const cv = eg.coverage || {};
  const cvLine = (c) => !c ? "–" : typeof c === "string" ? esc(c) : `<span class="tag ${c.ok ? "ok" : "warn"}">${c.ok ? "collecte OK" : "indisponible"}</span> ${esc(c.method || "")}`;
  setHTML($("#eg-coverage"), `<ul class="ai-list"><li><b>NAS</b> : ${cvLine(cv.nas)}</li><li><b>Homelab</b> : ${cvLine(cv.homelab)}</li><li><b>clawhost</b> : ${cvLine(cv.clawhost)}</li></ul>${cv.note ? `<div class="hint">${esc(cv.note)}</div>` : ""}${(eg.errors || []).map((e) => `<div class="hint" style="color:var(--warn)">${esc(e)}</div>`).join("")}
    <div class="hint mt">Géolocalisation hors ligne (aucune IP envoyée à un tiers). ${esc(eg.attribution || "")}</div>`);
}

/* ===================================================================== IA & PRÉVISIONS */
const AI_STATE = { asking: false, answer: null };
async function aiPost(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-InfraDash": "1" }, body: JSON.stringify(body || {}) });
  return r.json();
}
const ETAT = { bon: ["ok", "Bon"], a_surveiller: ["warn", "À surveiller"], degrade: ["warn", "Dégradé"], critique: ["crit", "Critique"] };
const PROBA = { faible: "mute", moyenne: "warn", elevee: "crit" };
function renderAI(first) {
  if (!$("#ai-ask-btn").dataset.init) {
    $("#ai-ask-btn").dataset.init = 1;
    const ask = async () => {
      const q = $("#ai-q").value.trim(); if (!q || AI_STATE.asking) return;
      AI_STATE.asking = true; AI_STATE.answer = null; renderAI();
      try { AI_STATE.answer = await aiPost("/api/ai/ask", { question: q }); } catch (e) { AI_STATE.answer = { error: String(e) }; }
      AI_STATE.asking = false; renderAI();
    };
    $("#ai-ask-btn").addEventListener("click", ask);
    $("#ai-q").addEventListener("keydown", (e) => { if (e.key === "Enter") ask(); });
    $("#ai-card").addEventListener("click", async (e) => {
      const b = e.target.closest("[data-ai-run]"); if (!b) return;
      b.disabled = true; b.textContent = "Demande envoyée…";
      try { const r = await aiPost("/api/ai/run"); if (r && r.status) S.derived.ai = Object.assign({}, S.derived.ai || {}, r); } catch (err) { /* l'état suivant arrivera par le flux */ }
      renderAI();
    });
  }
  const a = D().ai || {}, r = a.result || {};
  const status = { ok: ["ok", "à jour"], en_cours: ["info", "analyse en cours…"], reportee: ["warn", "reportée"], erreur: ["crit", "erreur"], jamais: ["mute", "jamais lancée"] }[a.status] || ["mute", a.status || "en attente"];
  const et = ETAT[r.etat_global] || null;
  setHTML($("#ai-card"), `<div class="ai-head"><div class="ai-badge">${icon("ai")}</div><div><b>Analyse de l'IA locale</b><div class="cell-sub">${esc(a.model || "Ollama · NAS")}${a.finished ? " · " + fmtDate(a.finished) : ""}${a.duration_s ? " · " + nf0.format(a.duration_s) + " s" : ""}${a.trigger ? " · " + esc(a.trigger) : ""}</div></div>
      <span class="tag ${status[0]}" style="margin-left:auto">${status[1]}${a.status === "en_cours" ? ' <span class="ai-spin"></span>' : ""}</span>
      <button class="btn primary" data-ai-run ${a.status === "en_cours" ? "disabled" : ""}>Relancer l'analyse</button></div>
    ${a.status === "reportee" && a.gpu_check ? `<div class="hint mt">Reportée : ${esc(a.gpu_check.reason || "GPU occupé")} — nouvel essai automatique.</div>` : ""}
    ${a.status === "erreur" ? `<div class="hint mt" style="color:var(--crit)">${esc(a.error || "")}</div>` : ""}
    ${(() => { const v = D().vulns_refresh || {}, h = (a.history || []).slice(-1)[0];
      const ctxT = h ? h.t - (h.duration_s || 0) : a.result_t || a.finished || 0;   // instant où l'analyse a lu l'état
      return a.status !== "en_cours" && r.synthese && (v.last_change_t || 0) > ctxT
        ? `<div class="hint mt">Des vulnérabilités ont changé lors d'une revérification (${fmtDate(v.last_change_t)}), après cette analyse : relancez-la pour qu'elle en tienne compte.</div>` : ""; })()}
    ${r.synthese ? `<div class="ai-summary">${et ? `<span class="tag ${et[0]}">${et[1]}</span> ` : ""}${esc(r.synthese)}</div>` : (a.status === "en_cours" ? "" : '<div class="empty">Pas encore d\'analyse. Elle tourne toutes les 3 h sur le GPU du NAS quand il est libre, ou à la demande.</div>')}
    ${(r.risques || []).length ? `<h3>Risques anticipés</h3><div class="ai-risks">${r.risques.map((x) => `<div class="ai-risk"><div class="row-flex"><b>${esc(x.titre)}</b><span class="tag ${PROBA[x.probabilite] || "mute"}" style="margin-left:auto">${esc(x.probabilite || "")}</span><span class="tag mute">${esc(x.horizon || "")}</span>${x.auto ? '<span class="tag info" title="Priorité non citée par l\'IA : ajoutée par le dashboard pour ne rien oublier">ajouté par le dashboard</span>' : ""}</div>
      ${x.impact ? `<p>${esc(x.impact)}</p>` : ""}${x.enchainement ? `<p class="ai-chain"><b>Si rien n'est fait :</b> ${esc(x.enchainement)}</p>` : ""}${(x.signaux || []).length ? `<ul class="ai-facts">${x.signaux.map((sg) => `<li>${esc(sg)}</li>`).join("")}</ul>` : ""}${x.action ? `<div class="act">${esc(x.action)}</div>` : ""}</div>`).join("")}</div>` : ""}
    ${(r.actions_prioritaires || []).length ? `<h3>Actions prioritaires</h3><ol class="ai-actions">${r.actions_prioritaires.map((x) => `<li><b>${esc(x.action)}</b> ${x.hote ? `<span class="tag">${esc(HOST_LABEL[x.hote] || x.hote)}</span> ` : ""}<span class="tag mute">effort ${esc(x.effort || "?")}</span>${x.auto ? ' <span class="tag info">ajouté par le dashboard</span>' : ""}${x.pourquoi ? `<div class="cell-sub">${esc(x.pourquoi)}</div>` : ""}</li>`).join("")}</ol>` : ""}
    ${(r.points_positifs || []).length ? `<h3>Ce qui va bien</h3><ul class="ai-list">${r.points_positifs.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    ${(r.questions_ouvertes || []).length ? `<h3>Questions ouvertes</h3><ul class="ai-list">${r.questions_ouvertes.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}
    ${r.controle && r.version === 5 ? `<div class="ai-trust"><span>${icon("info")}</span><div>Les faits, actions et points positifs affichés sont vérifiés par le dashboard ; les titres, impacts et enchaînements sont rédigés par l'IA locale et peuvent être approximatifs. Faits cités : ${nf0.format(r.controle.faits_cites)}/${nf0.format(r.controle.faits_total)} · priorités couvertes ${nf0.format(r.controle.priorites)}/${nf0.format(r.controle.priorites)}${r.controle.ajouts_auto ? ` (dont ${r.controle.ajouts_auto} ajoutée(s) par le dashboard)` : ""} · ${nf0.format(r.controle.corrections || 0)} correction(s) automatique(s) (horizon, ordre, justification)${a.stats ? ` · ${esc(a.model || "")} : ${nf0.format(a.stats.prompt_tokens || 0)} tokens lus, ${nf0.format(a.stats.completion_tokens || 0)} générés à ${nf0.format(a.stats.tokens_per_s || 0)} tok/s${a.stats.think ? ", avec réflexion" : ""}` : ""}.</div></div>` : ""}`);
  $("#ai-model").textContent = a.model || "";
  const ans = AI_STATE.answer;
  setHTML($("#ai-answer"), AI_STATE.asking ? '<div class="hint"><span class="ai-spin"></span> L\'IA réfléchit (10 à 60 s sur le GPU du NAS)…</div>'
    : ans ? (ans.error ? `<div class="hint" style="color:var(--crit)">${esc(ans.error)}</div>` : `<div class="ai-summary">${esc(ans.answer || ans.reponse || ans.text || JSON.stringify(ans))}</div>${ans.duration_s ? `<div class="cell-sub">${nf0.format(ans.duration_s)} s · ${esc(ans.model || "")}</div>` : ""}`) : "");
  const g = a.gpu_check || {}, gpu = (SL().nas || {}).gpu || {};
  setHTML($("#ai-guard"), `<ul class="ai-list">
    <li>IA 100 % locale (Ollama sur le NAS) : aucune donnée ne sort du réseau.</li>
    <li>Lancement seulement si le GPU est disponible : utilisation &lt; 40 % et assez de VRAM libre (Jellyfin et Immich restent prioritaires).${g.util != null ? ` Dernier contrôle : GPU ${nf0.format(g.util)} %, ${nf0.format(g.vram_free_mb || 0)} Mo libres.` : ""}</li>
    <li>Modèle déchargé de la VRAM 2 min après l'analyse ; une seule analyse à la fois, 5 min minimum entre deux demandes.</li>
    <li>Lecture seule : l'IA propose, elle n'exécute rien.</li>
    <li>GPU maintenant : ${gpu.name ? `${esc(gpu.name)} · ${nf0.format(gpu.util || 0)} % · ${nf0.format(gpu.mem_used || 0)} / ${nf0.format(gpu.mem_total || 0)} Mo` : "–"}${a.next_run ? ` · prochaine analyse ${fmtDate(a.next_run)}` : ""}</li></ul>`);
  const fc = (D().forecasts || {}).items || [];
  const sevCls = { crit: "crit", warn: "warn", info: "info" };
  setHTML($("#fc-list"), fc.map((f, i) => `<div class="fc-card ${sevCls[f.severity] || ""}"><div class="row-flex"><b>${esc(f.title)}</b><span class="tag ${sevCls[f.severity] || "mute"}" style="margin-left:auto">${esc(f.horizon || "")}</span></div>
      <div class="fc-eta">${f.eta_days != null ? (f.eta_days < 1 ? "< 1 jour" : nf0.format(f.eta_days) + " jours") : "—"}</div>
      <div class="cell-sub">${esc(f.detail || "")}</div><canvas class="spark" data-fc="${i}"></canvas>
      <div class="cell-sub">Actuel : ${f.current != null ? esc(String(typeof f.current === "number" ? nf1.format(f.current) : f.current)) + " " + esc(f.unit || "") : "–"}${f.trend_per_day != null ? ` · tendance ${f.trend_per_day > 0 ? "+" : ""}${nf1.format(f.trend_per_day)} ${esc(f.unit || "")}/j` : ""} · confiance ${esc(f.confidence || "?")}</div></div>`).join("") || '<div class="empty">Calcul en cours…</div>');
  $$("canvas[data-fc]").forEach((cv) => { const f = fc[cv.dataset.fc]; sparkline(cv, (f.series || []).map((p) => (Array.isArray(p) ? p[1] : p)), f.severity === "crit" ? "#FF453A" : f.severity === "warn" ? "#FF9F0A" : "#4A9EFF"); });
}

/* ===================================================================== RÉSEAU LOCAL
   Un seul inventaire : présence en direct (table ARP du homelab, DNS du réseau) + identité NetScan rapprochée par MAC.
   Les CVE de NetScan sont triées côté serveur (netscan._digest) : retenues dans Vulnérabilités, écartées avec leur raison. */
const NS = { f: "all" };
function renderLan(first) {
  if (!$("#ns-filter").dataset.init) {
    $("#ns-filter").dataset.init = 1;
    segment($("#ns-filter"), (b) => { NS.f = b.dataset.f; renderLan(); });
    $("#ns-schema").addEventListener("click", () => setTimeout(() => setFlowMode("lan"), 50));
  }
  const ns = SL().netscan || {}, dg = ns.digest || {}, url = esc(ns.url || "http://192.168.2.5:3000");
  const dev = lanDevices().filter((d) => d.alive), todo = dev.filter((d) => !d.known), news = dev.filter((d) => d.flags.includes("nouveau"));
  setHTML($("#ns-kpis"), [
    ["Appareils présents", nf0.format(dev.length), "vus à l'instant par le homelab (DNS du réseau)", "var(--teal)"],
    ["À identifier", nf0.format(todo.length), "ni machine suivie, ni « connu » dans NetScan", todo.length ? "var(--warn)" : "var(--ok)"],
    ["Nouveaux", nf0.format(news.length), "présents mais jamais vus par NetScan", news.length ? "var(--warn)" : "var(--ok)"],
    ["Vulnérabilités", nf0.format((dg.active || []).length), `${nf0.format(dg.n_cve_dropped || 0)} CVE NetScan écartées (voir Vulnérabilités)`, (dg.active || []).length ? "var(--crit)" : "var(--ok)"],
  ].map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
  // À regarder : vulnérabilités retenues, services ouverts, appareils à identifier (résumé)
  const att = [...(dg.active || []).map((g) => ["crit", `${g.device} (${g.ip}) : ${g.product} ${g.version}`, `${g.n} CVE possibles, CVSS max ${nf1.format(g.max_cvss)}${g.why ? " — " + g.why : ""}`]),
    ...(dg.attention || []).map((x) => ["warn", `${x.device}${x.ip ? " (" + x.ip + ")" : ""} : ${x.title}`, x.detail || ""])];
  const anon = todo.filter((d) => d.name === "Appareil inconnu"), named = todo.filter((d) => d.name !== "Appareil inconnu");
  if (todo.length) att.push(["info", `${todo.length} appareil(s) à identifier`, [anon.length ? `${anon.length} sans nom (${anon.slice(0, 4).map((d) => d.ip).join(", ")}${anon.length > 4 ? "…" : ""})` : "", named.slice(0, 5).map((d) => d.name).join(", ") + (named.length > 5 ? "…" : "")].filter(Boolean).join(" ; ") + " — à nommer et marquer « connu » dans NetScan, ou à couper s'ils sont inconnus."]);
  $("#ns-att-sub").textContent = att.length ? `${att.length} point(s)` : "";
  setHTML($("#ns-att"), att.length ? att.map(([lv, t, d]) => `<div class="al ${lv}"><span class="dot ${lv === "info" ? "warn" : lv}"></span><div class="al-body"><b>${esc(t)}</b>${d ? `<div class="cell-sub">${esc(d)}</div>` : ""}</div></div>`).join("") : '<div class="empty">Rien à signaler</div>');
  // NetScan : état de l'outil lui-même
  $("#ns-src-sub").textContent = ns.ok && dg.last_scan_ok ? `dernier scan réussi ${fmtDate(dg.last_scan_ok)}` : "";
  setHTML($("#ns-state"), !ns.configured ? `<p class="hint">Non connecté : créez ${esc(ns.file || "~/.config/infradash/netscan.json")} (voir README). Sans lui, la présence et les noms connus d'InfraDash restent affichés.</p>`
    : !ns.ok ? `<div class="al crit"><span class="dot crit"></span><div class="al-body"><b>NetScan injoignable</b><div class="cell-sub">${esc(ns.error || "")}</div></div></div>`
    : ((dg.issues || []).map((i) => `<div class="al ${i.level}"><span class="dot ${i.level === "info" ? "warn" : i.level}"></span><div class="al-body"><b>${esc(i.title)}</b><div class="cell-sub">${esc(i.detail)}</div>${i.fix ? `<div class="act">${esc(i.fix)}</div>` : ""}</div></div>`).join("")
      || '<div class="hint">NetScan fonctionne normalement.</div>') + `<div class="hint mt">Lecture seule via son API · <a href="${url}" target="_blank" rel="noopener">ouvrir NetScan</a></div>`);
  // Appareils présents, par famille
  const list = NS.f === "todo" ? todo : NS.f === "new" ? news : dev, bad = lanBad();
  $("#ns-dev-sub").textContent = `${list.length} / ${dev.length}`;
  const fam = {}; list.forEach((d) => (fam[d.cat] = fam[d.cat] || []).push(d));
  setHTML($("#ns-devices"), Object.keys(fam).length ? `<div class="ns-fams">${Object.entries(fam).sort((x, y) => y[1].length - x[1].length).map(([c, ds]) => `<div class="ns-fam"><div class="lbl">${esc(c)} · ${ds.length}</div>
    ${ds.map((d) => `<div class="ns-dev"><span class="dot ${bad.has(d.mac) ? "crit" : d.known ? "ok" : "warn"}"></span><div><b>${esc(d.name)}</b>${d.flags.includes("nouveau") ? ' <span class="tag warn">nouveau</span>' : ""}<div class="cell-sub mono">${esc(d.ip || "")}${d.vendor && d.vendor !== d.name ? ` · ${esc(d.vendor)}` : ""}${d.flags.includes("ip") ? ` · était ${esc(d.ns_ip)}` : ""}</div></div></div>`).join("")}</div>`).join("")}</div>` : '<div class="empty">Aucun</div>');
}

const RENDER = { overview: renderOverview, flows: renderFlows, machines: renderMachines, containers: renderContainers, planning: renderPlanning,
  storage: renderStorage, backups: renderBackups, network: renderNetwork, insights: renderInsights, journal: renderJournal, vulns: renderVulns, ai: renderAI,
  scores: renderScores, egress: renderEgress, lan: renderLan };
let renderBusy = false;
const Views = {
  render(view, first) {
    if (!S.ready) return;
    try { RENDER[view] && RENDER[view](first); } catch (e) { console.error("rendu", view, e); }
  },
  tick(full) {
    const hs = healthScore();
    const pill = $("#health-pill");
    pill.querySelector(".dot").className = "dot " + (hs.crit ? "crit" : hs.warn ? "warn" : "ok");
    pill.querySelector(".score").textContent = (hs.grade ? hs.grade + " · " : "") + hs.score + "/100";
    const b = $('[data-badge="insights"]');
    if (b) { b.hidden = !(hs.crit + hs.warn); b.textContent = hs.crit + hs.warn; b.className = "badge" + (hs.crit ? "" : " warn"); }
    const bb = $('[data-badge="backups"]'); const bc = ((D().backups || {}).chains || []).filter((c) => c.status !== "ok").length;
    if (bb) { bb.hidden = !bc; bb.textContent = bc; }
    renderBell();
    $("#side-foot").innerHTML = `Hébergé sur homelab:7070<br>Lecture seule · ${Object.keys(S.collectors || {}).length} collecteurs<br>MAJ ${new Date((S.t || 0) * 1000).toLocaleTimeString("fr-FR")}`;
    if (renderBusy) return;
    renderBusy = true;
    requestAnimationFrame(() => {
      // les vues lourdes ne sont rafraîchies qu'aux mises à jour complètes
      if (full || ["overview", "flows", "machines", "storage", "network"].includes(CURRENT) || (CURRENT === "containers" && Date.now() - (UI.ctT || 0) > 4000)) {
        if (CURRENT === "containers") UI.ctT = Date.now();
        if (CURRENT !== "planning" || full) Views.render(CURRENT, false);
      }
      if (full) UI.lastEvT = Math.max(UI.lastEvT, ...(S.events || []).map((e) => e.t), 0);
      renderBusy = false;
    });
  },
  second() {
    const now = Date.now() / 1000;
    $$("[data-cd]").forEach((el) => { el.textContent = fmtCountdown(+el.dataset.cd - now); });
  },
};
window.Views = Views;
