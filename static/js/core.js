/* InfraDash — noyau : état, flux SSE, navigation, formatage, petits composants graphiques */
"use strict";

const S = { live: {}, slow: {}, derived: {}, topology: null, events: [], collectors: {}, t: 0, ready: false };
const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;

/* palette sobre : couleurs système (iOS, thème sombre), toujours en #rrggbb (les moteurs y ajoutent une opacité hexadécimale) */
const PROTO = {
  lan: ["#4A9EFF", "LAN"], uplink: ["#4A9EFF", "LAN"], smb: ["#FF9F0A", "SMB"], ssh: ["#30D158", "SSH"], https: ["#64D2FF", "HTTPS / WAN"],
  http: ["#8EC5FF", "HTTP"], dns: ["#FFD60A", "DNS"], tailscale: ["#BF5AF2", "Tailscale"], media: ["#FF375F", "Média"],
  db: ["#AC8E68", "Base de données"], metrics: ["#66D4CF", "Métriques"], ai: ["#7D7AFF", "IA / OpenClaw"], domotique: ["#A3D977", "Domotique"],
  probe: ["#8E8E93", "Sondes"], tcp: ["#7F9CC4", "TCP"], torrent: ["#F2785C", "Torrent"],
};
const CAT_COLOR = {
  media: "#FF375F", download: "#FF9F0A", apps: "#4A9EFF", db: "#AC8E68", infra: "#BF5AF2", ia: "#7D7AFF", dev: "#30D158",
  securite: "#66D4CF", domotique: "#A3D977", autre: "#8E8E93",
};
const JOB_COLOR = {
  backup: "#30D158", stockage: "#FF9F0A", maintenance: "#BF5AF2", supervision: "#4A9EFF", media: "#FF375F", apps: "#64D2FF",
  systeme: "#8E8E93", script: "#636366", autre: "#8E8E93", planning: "#FFD60A",
};
/* couleur #rgb/#rrggbb + opacité (0–1) -> rgba() ; renvoie la couleur telle quelle si ce n'est pas de l'hexadécimal */
function withAlpha(color, a) {
  const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(color || "");
  if (!m) return color;
  let h = m[1]; if (h.length === 3) h = h.replace(/./g, (c) => c + c);
  const n = parseInt(h, 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${Math.max(0, Math.min(1, a)).toFixed(3)})`;
}
const JOB_LABEL = { backup: "Sauvegarde", stockage: "Stockage", maintenance: "Maintenance", supervision: "Supervision", media: "Médias",
  apps: "Applis", systeme: "Système", script: "Script", autre: "Autre" };
const HOST_LABEL = { homelab: "Homelab", nas: "NAS", clawhost: "clawhost", tailscale: "Tailscale", internet: "Internet", lan: "Réseau local" };

/* ---------- formatage ---------- */
const nf1 = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 });
const nf0 = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 0 });
function fmtBytes(b, dec = 1) {
  if (b == null || isNaN(b)) return "–";
  const u = ["o", "ko", "Mo", "Go", "To", "Po"];
  let i = 0; b = Number(b);
  while (Math.abs(b) >= 1000 && i < u.length - 1) { b /= 1000; i++; }
  return (i === 0 ? nf0.format(b) : new Intl.NumberFormat("fr-FR", { maximumFractionDigits: b < 10 ? dec : 0 }).format(b)) + " " + u[i];
}
const fmtRate = (b) => (b == null ? "–" : fmtBytes(b) + "/s");
const fmtPct = (v) => (v == null || isNaN(v) ? "–" : nf1.format(v) + " %");
function fmtDur(sec) {
  if (sec == null || isNaN(sec)) return "–";
  sec = Math.abs(sec);
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d} j ${h} h`;
  if (h) return `${h} h ${String(m).padStart(2, "0")}`;
  if (m) return `${m} min`;
  return `${Math.floor(sec)} s`;
}
function fmtCountdown(sec) {
  if (sec == null) return "–";
  if (sec < 0) return "en cours";
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = Math.floor(sec % 60);
  if (h >= 24) return fmtDur(sec);
  if (h) return `${h} h ${String(m).padStart(2, "0")}`;
  return m >= 10 ? `${m} min` : `${m}:${String(s).padStart(2, "0")}`;
}
const fmtTime = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" }) : "–");
function fmtDate(ts, withTime = true) {
  if (!ts) return "–";
  const d = new Date(ts * 1000);
  const today = new Date(); const tom = new Date(Date.now() + 86400000); const yest = new Date(Date.now() - 86400000);
  const same = (a, b) => a.toDateString() === b.toDateString();
  const t = d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
  if (same(d, today)) return withTime ? `aujourd'hui ${t}` : "aujourd'hui";
  if (same(d, tom)) return withTime ? `demain ${t}` : "demain";
  if (same(d, yest)) return withTime ? `hier ${t}` : "hier";
  return d.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" }) + (withTime ? " " + t : "");
}
const ago = (ts) => (ts ? "il y a " + fmtDur(Date.now() / 1000 - ts) : "–");
const lvlColor = (l) => ({ crit: "var(--crit)", warn: "var(--warn)", ok: "var(--ok)", info: "var(--info)" }[l] || "var(--muted)");
const pctClass = (p, w = 75, c = 90) => (p >= c ? "crit" : p >= w ? "warn" : "");
const icon = (id, cls = "") => `<svg class="${cls}"><use href="#i-${id}"/></svg>`;

/* ---------- composants ---------- */
/* jauges où « haut = bien » (disponibilité, sondes OK) : pas de passage en orange/rouge au-delà de 75/90 % */
const RING_HIGH_GOOD = /^(sondes|dispo)/i;
const ringColor = (v, base, fixed) => (fixed ? base : v > 90 ? "var(--crit)" : v > 75 ? "var(--warn)" : base);
function ring(value, label, color, size = 74) {
  const r = size / 2 - 4, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, value || 0));
  const base = color || "var(--cyan)", fixed = RING_HIGH_GOOD.test(label || "");
  const col = ringColor(v, base, fixed);
  // anneau fin et plat : piste discrète + arc coloré, sans lueur
  return `<div class="ring" style="width:${size}px;height:${size}px"><svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="5"/>
    <circle class="fg" data-base="${base}"${fixed ? ' data-fixed="1"' : ""} cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${col}" style="color:${col}" stroke-width="5" stroke-linecap="round"
      stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - v / 100)}"/></svg>
    <div class="rv"><div>${value == null ? "–" : nf0.format(value)}<span style="font-size:10px">${value == null ? "" : "%"}</span><small>${label}</small></div></div></div>`;
}
function updateRing(el, value) {
  if (!el) return;
  const fg = el.querySelector("circle.fg"); const r = +fg.getAttribute("r"); const c = 2 * Math.PI * r;
  const v = Math.max(0, Math.min(100, value || 0));
  fg.style.strokeDashoffset = c * (1 - v / 100);
  const col = ringColor(v, fg.dataset.base || "var(--cyan)", !!fg.dataset.fixed);
  fg.setAttribute("stroke", col); fg.style.color = col;
  el.querySelector(".rv div").firstChild.textContent = value == null ? "–" : nf0.format(value);
}

/* mini-graphe canvas (série de valeurs) */
function sparkline(canvas, values, color = "#64D2FF", opts = {}) {
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 90, h = canvas.clientHeight || 24;
  if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  const vals = (values || []).map((v) => (v == null ? null : +v));
  const nums = vals.filter((v) => v != null);
  if (nums.length < 2) return;
  const max = Math.max(opts.min || 0, ...nums) * 1.08 || 1;
  const step = w / (vals.length - 1);
  const pts = vals.map((v, i) => [i * step, v == null ? null : h - 2 - (v / max) * (h - 4)]);
  // trait net de 1,25 px + voile très léger dessous, sans ombre
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, withAlpha(color, 0.22)); grad.addColorStop(1, withAlpha(color, 0));
  ctx.beginPath();
  let started = false;
  pts.forEach(([x, y]) => { if (y == null) return; if (!started) { ctx.moveTo(x, y); started = true; } else ctx.lineTo(x, y); });
  ctx.lineJoin = "round"; ctx.lineCap = "round";
  ctx.strokeStyle = color; ctx.lineWidth = 1.25; ctx.stroke();
  ctx.lineTo(pts[pts.length - 1][0], h); ctx.lineTo(pts.findIndex((p) => p[1] != null) * step, h); ctx.closePath();
  ctx.fillStyle = grad; ctx.fill();
  // point "live" sur la dernière valeur
  const last = pts[pts.length - 1];
  if (last[1] != null && !opts.noDot) { ctx.beginPath(); ctx.arc(last[0] - 1.5, last[1], 2, 0, 6.29); ctx.fillStyle = color; ctx.fill(); }
}

/* info-bulle */
const TIP = { el: null };
function showTip(html, x, y) {
  TIP.el = TIP.el || $("#tip");
  TIP.el.innerHTML = html;
  TIP.el.classList.add("on");
  const r = TIP.el.getBoundingClientRect();
  let nx = x + 16, ny = y + 14;
  if (nx + r.width > innerWidth - 8) nx = x - r.width - 16;
  if (ny + r.height > innerHeight - 8) ny = y - r.height - 14;
  TIP.el.style.left = Math.max(8, nx) + "px"; TIP.el.style.top = Math.max(8, ny) + "px";
}
const hideTip = () => TIP.el && TIP.el.classList.remove("on");

/* Presse-papiers : l'API Clipboard n'existe qu'en HTTPS ou sur localhost. En HTTP sur le LAN (http://192.168.2.4:7070),
   repli sur execCommand("copy") via une zone de texte temporaire ; à défaut, le texte est sélectionné pour un Ctrl+C. */
async function copyText(txt) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(txt); return true; } catch (e) { /* repli ci-dessous */ }
  }
  const ta = document.createElement("textarea"), prev = document.activeElement;
  ta.value = txt; ta.setAttribute("readonly", "");
  ta.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;padding:0;border:0;font-size:16px;opacity:0;pointer-events:none";
  document.body.appendChild(ta);
  ta.select(); ta.setSelectionRange(0, txt.length);
  let ok = false;
  try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
  ta.remove();
  if (prev && prev.focus) prev.focus({ preventScroll: true });
  return ok;
}
document.addEventListener("click", (e) => {   // boutons « Copier » des vues sans gestionnaire propre (machines, réseau local…)
  const c = e.target.closest("[data-copy]");
  if (c && !c.closest("#v-vulns, #v-egress")) copyFromBtn(c);
});
async function copyFromBtn(btn) {
  const ok = await copyText(btn.dataset.copy || "");
  const pre = !ok && btn.parentElement && btn.parentElement.querySelector("pre");
  if (pre) { const r = document.createRange(); r.selectNodeContents(pre); const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r); }
  btn.textContent = ok ? "Copié" : "Sélectionné : copiez-le";
  btn.classList.toggle("copied", ok);
  clearTimeout(btn._t);
  btn._t = setTimeout(() => { btn.textContent = "Copier"; btn.classList.remove("copied"); }, ok ? 1500 : 5000);
  return ok;
}

/* compteur animé */
function tween(el, to, fmt = (v) => nf0.format(v), ms = 700) {
  if (!el) return;
  const from = parseFloat(el.dataset.v || "0");
  el.dataset.v = to;
  if (REDUCED || from === to || isNaN(to)) { el.textContent = fmt(to); return; }
  const t0 = performance.now();
  const step = (t) => {
    const k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3);
    el.textContent = fmt(from + (to - from) * e);
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* ---------- ECharts ---------- */
const CHARTS = new Map();
function chart(el) {
  if (!el) return null;
  CHARTS.forEach((x, e) => { if (!e.isConnected) { if (!x.isDisposed()) x.dispose(); CHARTS.delete(e); } });  // graphes retirés du DOM
  let c = CHARTS.get(el);
  if (!c || c.isDisposed()) { c = echarts.init(el, null, { renderer: "canvas" }); CHARTS.set(el, c); }
  return c;
}
addEventListener("resize", () => { CHARTS.forEach((c) => !c.isDisposed() && c.resize()); });
/* thème des graphes : grilles discrètes, couleurs système, aucune ombre ni lueur */
const CHART_FONT = '-apple-system, BlinkMacSystemFont, "Geist", ui-sans-serif, system-ui, sans-serif';
const CHART_MONO = 'ui-monospace, SFMono-Regular, "Geist Mono", Menlo, monospace';
const TAX = { type: "time", axisLine: { lineStyle: { color: "rgba(255,255,255,.10)" } }, axisTick: { show: false }, splitLine: { show: false },
  axisLabel: { color: "#8e8e93", fontSize: 11, fontFamily: CHART_MONO, hideOverlap: true } };
const AX = {
  axisLine: { lineStyle: { color: "rgba(255,255,255,.10)" } }, axisTick: { show: false },
  axisLabel: { color: "#8e8e93", fontSize: 11, fontFamily: CHART_MONO }, splitLine: { lineStyle: { color: "rgba(255,255,255,.05)" } },
};
function baseOpt(extra = {}) {
  return Object.assign({
    animationDuration: 500, animationEasing: "cubicOut",
    color: ["#4A9EFF", "#30D158", "#FF9F0A", "#BF5AF2", "#FF375F", "#64D2FF", "#FFD60A", "#66D4CF"],
    textStyle: { fontFamily: CHART_FONT, color: "#c7c7cc" },
    grid: { left: 48, right: 16, top: 28, bottom: 26 },
    tooltip: { trigger: "axis", backgroundColor: "rgba(35,35,37,.97)", borderColor: "#313134", borderWidth: 1, padding: [8, 11],
      textStyle: { color: "#f5f5f7", fontSize: 12, fontFamily: CHART_FONT },
      extraCssText: "border-radius:10px;box-shadow:0 14px 34px -10px rgba(0,0,0,.85);backdrop-filter:blur(20px);",
      axisPointer: { lineStyle: { color: "rgba(255,255,255,.22)", width: 1 }, shadowStyle: { color: "rgba(255,255,255,.04)" } } },
    legend: { top: 0, right: 0, textStyle: { color: "#c7c7cc", fontSize: 11.5 }, icon: "circle", itemWidth: 7, itemHeight: 7, itemGap: 14,
      inactiveColor: "#48484a", pageIconColor: "#c7c7cc", pageIconInactiveColor: "#48484a", pageIconSize: 10, pageTextStyle: { color: "#8e8e93" } },
  }, extra);
}
function lineSeries(name, data, color, area = true, extra = {}) {
  return Object.assign({
    name, type: "line", data, showSymbol: false, symbol: "circle", symbolSize: 5, smooth: 0.3, sampling: "lttb",
    lineStyle: { width: 1.5, color }, itemStyle: { color }, emphasis: { focus: "none", lineStyle: { width: 1.5 } },
    areaStyle: area ? { color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [{ offset: 0, color: withAlpha(color, 0.18) }, { offset: 1, color: withAlpha(color, 0) }]) } : undefined,
  }, extra);
}
async function history(key, host, range) {
  try {
    const r = await fetch(`/api/history?key=${encodeURIComponent(key)}&host=${encodeURIComponent(host || "")}&range=${range}`);
    return await r.json();
  } catch (e) { return { series: [] }; }
}

/* ---------- navigation ---------- */
const VIEWS = [
  ["overview", "Vue d'ensemble", "overview"], ["scores", "Notes & axes", "gauge"], ["flows", "Flux live", "flows"],
  ["machines", "Machines", "cpu"], ["containers", "Port Docker", "ship"], ["vulns", "Vulnérabilités", "bug"],
  ["egress", "Flux sortants", "map"], ["ai", "IA & prévisions", "ai"], ["planning", "Planning & crons", "cal"],
  ["storage", "Stockage & montages", "db"], ["backups", "Sauvegardes", "backup"], ["network", "Réseau & exposition", "globe"], ["lan", "Réseau local", "router"],
  ["insights", "Diagnostics", "alert"], ["journal", "Journal", "list"],
];
const SUBS = {
  overview: "Toute l'infra en un coup d'œil", flows: "Qui parle à qui, en temps réel", machines: "Ressources, capteurs, historique",
  containers: "Tous les conteneurs Docker des 3 machines", planning: "Crons, timers systemd, User Scripts : quoi, quand, pourquoi",
  storage: "Array, parité, partages, montages réseau", backups: "Chaînes de sauvegarde, fraîcheur, volumes",
  network: "Tailscale, DNS, latences, domaines publics", lan: "Qui est sur le réseau en ce moment, avec l'identité donnée par NetScan", insights: "Ce qui mérite votre attention", journal: "Historique des changements détectés",
  scores: "Santé, sécurité, résilience, maintenance, confidentialité : la note et comment la remonter",
  vulns: "CVE et fins de vie corrélées à vos versions réelles, avec le plan de correction",
  egress: "Où partent vos données, et comment le bloquer", ai: "L'IA locale analyse la situation et anticipe les problèmes",
};
let CURRENT = "overview";
function buildNav() {
  const html = VIEWS.map(([id, label, ic]) => `<a href="#${id}" data-v="${id}">${icon(ic)}<span>${label}</span><span class="badge" data-badge="${id}" hidden></span></a>`).join("");
  $("#nav").innerHTML = html;
  $("#mnav").innerHTML = VIEWS.map(([id, label, ic]) => `<a href="#${id}" data-v="${id}">${icon(ic)}<span>${label.split(" ")[0]}</span></a>`).join("");
}
function route() {
  const id = (location.hash || "#overview").slice(1).split("/")[0];
  CURRENT = VIEWS.some((v) => v[0] === id) ? id : "overview";
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === "v-" + CURRENT));
  $$("[data-v]").forEach((a) => a.classList.toggle("active", a.dataset.v === CURRENT));
  const v = VIEWS.find((x) => x[0] === CURRENT);
  $("#view-title").textContent = v[1];
  $("#view-sub").textContent = SUBS[CURRENT];
  document.title = `${v[1]} · InfraDash`;
  window.scrollTo({ top: 0 });
  if (window.Views) Views.render(CURRENT, true);
}
function segment(el, cb) {
  el.addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    if (!b.dataset.o) $$("button", el).forEach((x) => x.classList.toggle("on", x === b));
    else b.classList.toggle("on");
    cb(b);
  });
}

/* ---------- flux de données ---------- */
let lastMsg = 0;
function apply(msg, full) {
  S.t = msg.t;
  S.live = Object.assign({}, S.live, msg.live || {});  // fusion : certaines clés ne sont pas envoyées à chaque fois
  if (msg.topology) S.topology = msg.topology;
  if (full) { S.slow = msg.slow || {}; S.derived = msg.derived || {}; S.events = msg.events || []; S.collectors = msg.collectors || {}; S.uptime = msg.uptime; }
  if (full && msg.build) {   // nouvelle version déployée : rechargement, sinon l'ancien code reste en mémoire dans l'onglet
    if (S.build && msg.build !== S.build) S.reload = true; else S.build = msg.build;
  }
  if (S.reload && !/^(INPUT|TEXTAREA|SELECT)$/.test((document.activeElement || {}).tagName || "")) { location.reload(); return; }
  S.ready = true; lastMsg = Date.now();
  if (window.Views) Views.tick(full);
}
async function boot() {
  buildNav();
  addEventListener("hashchange", route);
  try { apply(await (await fetch("/api/state")).json(), true); } catch (e) { /* le flux prendra le relais */ }
  route();
  connect();
  setInterval(() => {
    $("#clock").textContent = new Date().toLocaleTimeString("fr-FR");
    const age = (Date.now() - lastMsg) / 1000;
    const dot = $("#conn-pill .dot");
    dot.className = "dot live " + (age < 6 ? "ok" : age < 20 ? "warn" : "crit");
    $("#conn-txt").textContent = age < 6 ? "temps réel" : age < 20 ? "ralenti…" : "déconnecté";
    if (window.Views) Views.second();
  }, 1000);
}
function connect() {
  const es = new EventSource("/api/stream");
  es.addEventListener("live", (e) => apply(JSON.parse(e.data), false));
  es.addEventListener("full", (e) => apply(JSON.parse(e.data), true));
  es.onerror = () => { es.close(); setTimeout(connect, 3000); };
}
document.addEventListener("DOMContentLoaded", boot);
