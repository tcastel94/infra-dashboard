/* InfraDash — moteurs graphiques animés (version sobre) : topologie des flux, galaxie de conteneurs, horloge des tâches, pipeline de sauvegarde */
"use strict";

const ENGINES = new Set();
let lastFrame = performance.now();
function rafLoop(t) {
  const dt = Math.min(0.05, (t - lastFrame) / 1000);
  lastFrame = t;
  ENGINES.forEach((e) => { if (e.el.offsetParent !== null) e.frame(dt, t / 1000); });
  requestAnimationFrame(rafLoop);
}
requestAnimationFrame(rafLoop);

const FX_FONT = '-apple-system, BlinkMacSystemFont, "Geist", ui-sans-serif, system-ui, sans-serif';
const TAU = Math.PI * 2;

/* pastille pleine pré-calculée par couleur (conservée pour compatibilité ; plus de sprite lumineux) */
const SPRITES = {};
function sprite(color) {
  if (SPRITES[color]) return SPRITES[color];
  const c = document.createElement("canvas"); c.width = c.height = 32;
  const g = c.getContext("2d");
  g.fillStyle = color; g.beginPath(); g.arc(16, 16, 15, 0, TAU); g.fill();
  return (SPRITES[color] = c);
}
const intensity = (rate) => (rate > 0 ? Math.log10(1 + rate / 800) : 0); // 1 ko/s≈0.35, 100 ko/s≈2.1, 10 Mo/s≈4.1

/* point qui circule + très légère traînée (deux segments dégressifs), en coordonnées déjà transformées */
function drawDot(g, x, y, bx, by, mx, my, r, col, a, tail) {
  if (tail && a > 0.05) {
    g.strokeStyle = col; g.lineCap = "round"; g.lineWidth = r * 1.3;
    g.globalAlpha = a * 0.12; g.beginPath(); g.moveTo(bx, by); g.lineTo(mx, my); g.stroke();
    g.globalAlpha = a * 0.3; g.beginPath(); g.moveTo(mx, my); g.lineTo(x, y); g.stroke();
  }
  g.globalAlpha = a; g.fillStyle = col; g.beginPath(); g.arc(x, y, r, 0, TAU); g.fill();
}

/* ===================================================================== TOPOLOGIE */
const LAYOUT = {
  wide: { W: 1600, H: 960, n: { internet: [800, 66], vps: [1310, 128], mobile: [290, 128], box: [800, 318], homelab: [380, 545],
    nas: [800, 645], clawhost: [1220, 545], pc: [150, 790], lan: [1450, 790], ha: [1075, 815] } },
  tall: { W: 1000, H: 1330, n: { internet: [500, 90], vps: [850, 175], mobile: [150, 175], box: [500, 360], homelab: [195, 640],
    clawhost: [805, 640], nas: [500, 860], pc: [140, 1110], lan: [860, 1110], ha: [500, 1150] } },
};
const NODE_STYLE = {
  internet: ["cloud", "#AEAEB2"], box: ["router", "#4A9EFF"], homelab: ["server", "#64D2FF"], nas: ["nas", "#BF5AF2"],
  clawhost: ["claw", "#FF375F"], pc: ["pc", "#4A9EFF"], lan: ["devices", "#66D4CF"], ha: ["home", "#66D4CF"],
  vps: ["vps", "#7D7AFF"], mobile: ["phone", "#30D158"],
};
const HOST_NODES = new Set(["homelab", "nas", "clawhost"]);
const ARC_LEN = 2 * Math.PI * 48; // périmètre de l'arc CPU (viewBox 100, r = 48)

class Topology {
  constructor(el, opts = {}) {
    this.el = el; this.opts = Object.assign({ small: false, labels: true, turbo: false, onNode: null }, opts);
    el.innerHTML = `<canvas class="bg"></canvas><canvas class="fx"></canvas><div class="nodes"></div>
      <div class="legend"></div>`;
    this.bg = el.querySelector("canvas.bg"); this.fx = el.querySelector("canvas.fx");
    this.nodesEl = el.querySelector(".nodes"); this.legendEl = el.querySelector(".legend");
    this.edges = new Map(); this.particles = []; this.nodeEls = {}; this.hover = null; this.dirty = true;
    this.ro = new ResizeObserver(() => this.resize()); this.ro.observe(el);
    el.addEventListener("mousemove", (e) => this.onMove(e));
    el.addEventListener("mouseleave", () => { this.hover = null; hideTip(); this.applyHover(); });
    el.addEventListener("click", (e) => { const n = e.target.closest(".tnode"); if (n && this.opts.onNode) this.opts.onNode(n.dataset.id); });
    ENGINES.add(this);
    this.resize();
  }
  layout() { return this.el.clientWidth < 640 && !this.opts.small ? LAYOUT.tall : LAYOUT.wide; }
  resize() {
    const cw = this.el.clientWidth, ch = this.el.clientHeight; if (!cw || !ch) return;
    const L = this.layout(); this.L = L;
    // bande réservée en bas pour la légende ; pastilles réduites quand le dessin est petit (mobile)
    const reserve = this.opts.small ? 0 : L === LAYOUT.tall ? 58 : 26;
    this.s = Math.min(cw / L.W, (ch - reserve) / L.H); this.ox = (cw - L.W * this.s) / 2; this.oy = (ch - reserve - L.H * this.s) / 2;
    this.k = this.opts.small ? 1 : Math.max(0.6, Math.min(1, this.s / 0.5));
    this.el.style.setProperty("--k", this.k.toFixed(3));
    this.dpr = Math.min(2, window.devicePixelRatio || 1);
    for (const c of [this.bg, this.fx]) { c.width = cw * this.dpr; c.height = ch * this.dpr; }
    this.cw = cw; this.ch = ch; this.dirty = true; this.edges.forEach((e) => (e.geom = null));
    Object.entries(this.nodeEls).forEach(([id, n]) => this.placeNode(id, n));
  }
  w2s([x, y]) { return [this.ox + x * this.s, this.oy + y * this.s]; }
  pos(id) {
    if (this.opts.small && id === "internet") return [800, 112];
    return this.L.n[id] || [this.L.W / 2, this.L.H / 2];
  }

  /* ----- données ----- */
  setData(topo) {
    if (!topo || !this.L) return;
    const seen = new Set();
    const pairCount = {};
    topo.edges.forEach((e) => { const k = [e.from, e.to].sort().join("|"); pairCount[k] = (pairCount[k] || 0) + 1; });
    const pairIdx = {};
    for (const e of topo.edges) {
      if (!this.L.n[e.from] || !this.L.n[e.to]) continue;
      if (this.opts.small && e.kind === "tailscale" && e.ab + e.ba < 500) continue;
      seen.add(e.id);
      const k = [e.from, e.to].sort().join("|"); pairIdx[k] = (pairIdx[k] || 0) + 1;
      let E = this.edges.get(e.id);
      if (!E) { E = { id: e.id, ab: 0, ba: 0, acc: [0, 0], geom: null }; this.edges.set(e.id, E); this.dirty = true; }
      Object.assign(E, { from: e.from, to: e.to, proto: e.proto, kind: e.kind, label: e.label, estimated: e.estimated, conns: e.conns, detail: e.detail,
        tab: e.ab, tba: e.ba, dup: pairCount[k], dupIdx: pairIdx[k] - 1 });
    }
    for (const id of [...this.edges.keys()]) if (!seen.has(id)) { const E = this.edges.get(id); if (E.labelEl) E.labelEl.remove(); this.edges.delete(id); this.dirty = true; }
    // nœuds : pastilles plates avec icône ; les hôtes portent un arc CPU fin (indicateur d'activité)
    const ids = new Set(); this.edges.forEach((e) => { ids.add(e.from); ids.add(e.to); });
    for (const id of ids) {
      let n = this.nodeEls[id];
      const info = (topo.nodes || {})[id] || {};
      if (!n) {
        const [ic, col] = NODE_STYLE[id] || ["server", "#4A9EFF"];
        n = document.createElement("div"); n.className = "tnode"; n.dataset.id = id;
        const size = this.opts.small ? (HOST_NODES.has(id) ? 50 : 38) : (HOST_NODES.has(id) ? 72 : 52);
        n.style.setProperty("--c", col); n.style.setProperty("--s", size + "px");
        n.innerHTML = `<div class="orb">${HOST_NODES.has(id) ? `<svg class="cpuarc" viewBox="0 0 100 100"><circle cx="50" cy="50" r="48" fill="none" stroke="rgba(255,255,255,.07)" stroke-width="2"/><circle class="arc" cx="50" cy="50" r="48" fill="none" stroke="${col}" stroke-width="2" stroke-linecap="round" stroke-dasharray="${ARC_LEN}" stroke-dashoffset="${ARC_LEN}" style="transition:stroke-dashoffset 1s"/></svg><div class="spin"></div>` : ""}${icon(ic, "ic")}</div>
          <div class="lbl"></div>${this.opts.small ? "" : '<div class="lsub"></div>'}<div class="lstat"></div>`;
        this.nodesEl.appendChild(n); this.nodeEls[id] = n; this.placeNode(id, n);
      }
      n.querySelector(".lbl").textContent = info.label || id;
      const sub = n.querySelector(".lsub"); if (sub) sub.textContent = info.sub || "";
      n.classList.toggle("down", info.up === false);
      n._info = info;
    }
    this.updateNodeStats();
    if (this.opts.labels && !this.opts.small) this.updateEdgeLabels();
    this.renderLegend();
  }
  placeNode(id, n) { if (!this.L) return; const [x, y] = this.w2s(this.pos(id)); n.style.left = x + "px"; n.style.top = y + "px"; }
  updateNodeStats() {
    const lv = S.live || {};
    const stat = {
      homelab: lv.homelab, nas: lv.nas && !lv.nas.down ? lv.nas : null, clawhost: lv.clawhost && lv.clawhost.metrics,
    };
    for (const [id, n] of Object.entries(this.nodeEls)) {
      const m = stat[id]; const st = n.querySelector(".lstat");
      let txt = "";
      if (m && m.cpu != null) {
        txt = `CPU ${nf0.format(m.cpu)} % · ↓${fmtRate(m.rx)}`;
        const arc = n.querySelector(".cpuarc circle.arc"); if (arc) arc.style.strokeDashoffset = ARC_LEN * (1 - Math.min(100, m.cpu) / 100);
        n.style.setProperty("--pulse", Math.max(0.9, 3.2 - m.cpu / 40).toFixed(2) + "s");
      } else if (id === "clawhost" && lv.clawhost) {
        const up = (lv.clawhost.probes || []).filter((p) => p.up).length;
        txt = `${up}/${(lv.clawhost.probes || []).length} sondes · ${lv.clawhost.ping != null ? nf1.format(lv.clawhost.ping) + " ms" : "pas de ping"}`;
      } else {
        let r = 0; this.edges.forEach((e) => { if (e.from === id || e.to === id) r += (e.tab || 0) + (e.tba || 0); });
        txt = r > 0 ? fmtRate(r) : "";
      }
      if (this.opts.small && id !== "nas" && id !== "homelab") txt = "";
      st.textContent = txt;
    }
  }
  updateEdgeLabels() {
    this.edges.forEach((E) => {
      if (!E.labelEl) { E.labelEl = document.createElement("div"); E.labelEl.className = "elabel"; this.nodesEl.appendChild(E.labelEl); }
      const tot = (E.tab || 0) + (E.tba || 0);
      E.labelEl.textContent = fmtRate(tot);
      E.labelEl.style.setProperty("--ec", (PROTO[E.proto] || PROTO.tcp)[0]);
      E.labelEl.classList.toggle("idle", tot < 1024 || !this.opts.labels);
    });
  }
  renderLegend() {
    const used = new Set(); this.edges.forEach((e) => used.add(e.proto));
    const html = [...used].map((p) => { const [c, l] = PROTO[p] || PROTO.tcp; return `<span><i style="background:${c}"></i>${l}</span>`; }).join("");
    if (this.opts.small) { this.legendEl.style.display = "none"; return; }
    if (this.legendEl.dataset.h !== html) { this.legendEl.innerHTML = html + '<span style="color:var(--muted)">- - - estimé</span>'; this.legendEl.dataset.h = html; }
  }

  /* ----- géométrie : courbe quadratique évitant les autres nœuds ----- */
  geom(E) {
    if (E.geom) return E.geom;
    const p0 = this.pos(E.from), p2 = this.pos(E.to);
    const dx = p2[0] - p0[0], dy = p2[1] - p0[1], len = Math.hypot(dx, dy) || 1;
    const nx = -dy / len, ny = dx / len, mx = (p0[0] + p2[0]) / 2, my = (p0[1] + p2[1]) / 2;
    const others = Object.entries(this.L.n).filter(([k]) => k !== E.from && k !== E.to).map(([, v]) => v);
    const base = E.dup > 1 ? (E.dupIdx - (E.dup - 1) / 2) * 0.22 : 0;
    const cands = [base + 0.1, base - 0.1, base + 0.24, base - 0.24, base + 0.38, base - 0.38, base + 0.55, base - 0.55];
    let best = null, bestD = -1;
    for (const k of cands) {
      const c = [mx + nx * k * len, my + ny * k * len];
      let dmin = 1e9;
      for (let i = 1; i < 20; i++) { const t = i / 20; const p = qpt(p0, c, p2, t); for (const o of others) dmin = Math.min(dmin, Math.hypot(p[0] - o[0], p[1] - o[1])); }
      if (dmin > 95) { best = c; break; }
      if (dmin > bestD) { bestD = dmin; best = c; }
    }
    const pts = []; for (let i = 0; i <= 40; i++) pts.push(qpt(p0, best, p2, i / 40));
    let arc = 0; for (let i = 1; i < pts.length; i++) arc += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
    E.geom = { p0, c: best, p2, pts, len: arc || 1 };
    E.geom.mid = qpt(p0, best, p2, this.labelT(E.geom));
    return E.geom;
  }
  /* position de l'étiquette de débit le long de la courbe : le milieu, sauf s'il chevauche une pastille ou sa légende */
  labelT(G) {
    const s = this.s || 1, k = this.k || 1, ids = Object.keys(this.nodeEls).length ? Object.keys(this.nodeEls) : Object.keys(this.L.n);
    // recouvrement (px²) entre deux rectangles [x0, x1, y0, y1]
    const ov = (a, b) => Math.max(0, Math.min(a[1], b[1]) - Math.max(a[0], b[0])) * Math.max(0, Math.min(a[3], b[3]) - Math.max(a[2], b[2]));
    let bestT = 0.5, bestCost = 1e12;
    for (let t = 0.2; t <= 0.801; t += 0.04) {
      const p = qpt(G.p0, G.c, G.p2, t);
      let cost = Math.abs(t - 0.5) * 300;      // légère préférence pour le milieu
      for (const id of ids) {
        const o = this.pos(id), r = ((HOST_NODES.has(id) ? 72 : 52) / 2) * k;
        const dx = (p[0] - o[0]) * s, dy = (p[1] - o[1]) * s;   // en pixels écran, relatifs au centre du nœud
        const kl = Math.max(0.8, k), lab = [dx - 34 * kl, dx + 34 * kl, dy - 11 * kl, dy + 11 * kl];
        cost += ov(lab, [-r - 2, r + 2, -r - 2, r + 2]) * 4;    // pastille : à éviter absolument
        cost += ov(lab, [-56 * k, 56 * k, r + 2, r + 54 * k]);  // légendes sous la pastille
      }
      if (cost < bestCost) { bestCost = cost; bestT = t; }
    }
    return bestT;
  }

  /* ----- rendu : liens fins (1–2 px écran), sans halo ni ombre ----- */
  drawStatic() {
    const g = this.bg.getContext("2d"), s = this.s, d = this.dpr, px = 1 / s;
    g.setTransform(1, 0, 0, 1, 0, 0); g.clearRect(0, 0, this.bg.width, this.bg.height);
    g.setTransform(d * s, 0, 0, d * s, d * this.ox, d * this.oy);
    g.lineCap = "round";
    this.edges.forEach((E) => {
      const G = this.geom(E), [col] = PROTO[E.proto] || PROTO.tcp;
      const tot = (E.ab || 0) + (E.ba || 0), I = intensity(tot);
      const hl = this.hover && (this.hover === E.id || this.hover === E.from || this.hover === E.to);
      const dim = this.hover && !hl;
      const a = dim ? 0.07 : hl ? 0.95 : I > 0.2 ? Math.min(0.62, 0.3 + I * 0.075) : 0.18;
      g.setLineDash(E.kind === "tailscale" ? [1.5 * px, 5 * px] : E.estimated ? [5 * px, 5 * px] : []);
      g.beginPath(); g.moveTo(G.p0[0], G.p0[1]); g.quadraticCurveTo(G.c[0], G.c[1], G.p2[0], G.p2[1]);
      g.strokeStyle = withAlpha(col, a); g.lineWidth = (hl ? 2 : I > 0.2 ? 1.2 + Math.min(0.4, I * 0.1) : 1) * px; g.stroke();
    });
    g.setLineDash([]);
    this.dirty = false;
  }
  frame(dt, now) {
    if (!this.L) return;
    // lissage des débits (les valeurs serveur arrivent toutes les 2 s)
    let changed = false;
    this.edges.forEach((E) => {
      for (const k of ["ab", "ba"]) {
        const tgt = E["t" + k] || 0, cur = E[k] || 0, nv = cur + (tgt - cur) * Math.min(1, dt * 2.2);
        if (Math.abs(intensity(nv) - intensity(cur)) > 0.02) changed = true;
        E[k] = nv;
      }
    });
    if (changed || this.dirty) this.drawStatic();
    const g = this.fx.getContext("2d"), d = this.dpr, s = this.s, px = 1 / s;
    g.setTransform(1, 0, 0, 1, 0, 0); g.globalCompositeOperation = "source-over"; g.globalAlpha = 1;
    g.clearRect(0, 0, this.fx.width, this.fx.height);
    g.setTransform(d * s, 0, 0, d * s, d * this.ox, d * this.oy);
    const turbo = this.opts.turbo ? 4 : 1, small = this.opts.small;
    // émission : densité et vitesse pilotées par le débit réel (échelle log)
    this.edges.forEach((E) => {
      ["ab", "ba"].forEach((dir, di) => {
        const rate = E[dir], I = intensity(rate);
        let emit = rate > 50 ? (0.45 + I * 1.5) * turbo : (E.kind === "uplink" || E.proto === "probe" ? 0.1 : 0.04);
        if (small) emit *= 0.7;
        if (REDUCED) emit = Math.min(emit, 0.4);
        E.acc[di] += emit * dt;
        while (E.acc[di] >= 1) {
          E.acc[di] -= 1;
          if (this.particles.length > 700) break;
          this.particles.push({ E, dir: di, t: 0, v: (0.13 + I * 0.055) * (0.9 + Math.random() * 0.2) * (small ? 1.2 : 1),
            r: (1.5 + Math.min(1.2, I * 0.28)) * (small ? 0.85 : 1), lane: (di ? -1 : 1) * (2 + Math.random() * 1.2), idle: rate <= 50 });
        }
      });
    });
    // déplacement + dessin
    const alive = [];
    for (const p of this.particles) {
      const E = p.E; if (!this.edges.has(E.id)) continue;
      p.t += p.v * dt; if (p.t >= 1) continue;
      const G = this.geom(E), sg = p.dir ? -1 : 1, tt = p.dir ? 1 - p.t : p.t;
      const [x, y] = qpt(G.p0, G.c, G.p2, tt), [tx, ty] = qder(G.p0, G.c, G.p2, tt);
      const l = Math.hypot(tx, ty) || 1, ox = (-ty / l) * p.lane * px, oy = (tx / l) * p.lane * px;
      const [col] = PROTO[E.proto] || PROTO.tcp;
      const fade = Math.min(1, p.t * 8, (1 - p.t) * 8);
      const dim = this.hover && !(this.hover === E.id || this.hover === E.from || this.hover === E.to);
      const a = fade * (p.idle ? 0.35 : 0.9) * (dim ? 0.12 : 1);
      // traînée : ~14 px écran derrière le point
      const tl = (14 * px) / G.len, tb = Math.max(0, Math.min(1, tt - sg * tl)), tm = Math.max(0, Math.min(1, tt - sg * tl * 0.45));
      const [bx, by] = qpt(G.p0, G.c, G.p2, tb), [mx, my] = qpt(G.p0, G.c, G.p2, tm);
      drawDot(g, x + ox, y + oy, bx + ox, by + oy, mx + ox, my + oy, p.r * px * (p.idle ? 0.8 : 1), col, a, !p.idle && !REDUCED);
      alive.push(p);
    }
    g.globalAlpha = 1;
    this.particles = alive;
    // étiquettes de débit
    if (!small) this.edges.forEach((E) => {
      if (!E.labelEl) return;
      const [x, y] = this.w2s(this.geom(E).mid);
      E.labelEl.style.left = x + "px"; E.labelEl.style.top = y + "px";
    });
  }

  /* ----- interaction ----- */
  onMove(e) {
    const r = this.el.getBoundingClientRect(); const mx = (e.clientX - r.left - this.ox) / this.s, my = (e.clientY - r.top - this.oy) / this.s;
    const nodeEl = e.target.closest(".tnode");
    let hit = null, html = "";
    if (nodeEl) {
      hit = nodeEl.dataset.id; html = this.nodeTip(hit);
    } else {
      let best = 22 / Math.max(this.s, 0.3);
      this.edges.forEach((E) => { for (const p of this.geom(E).pts) { const dd = Math.hypot(p[0] - mx, p[1] - my); if (dd < best) { best = dd; hit = E.id; } } });
      if (hit) html = this.edgeTip(this.edges.get(hit));
    }
    if (hit !== this.hover) { this.hover = hit; this.applyHover(); }
    if (hit) showTip(html, e.clientX, e.clientY); else hideTip();
  }
  applyHover() {
    this.dirty = true;
    Object.entries(this.nodeEls).forEach(([id, n]) => {
      let rel = !this.hover || this.hover === id;
      if (this.hover && !rel) this.edges.forEach((E) => { if ((E.id === this.hover || E.from === this.hover || E.to === this.hover) && (E.from === id || E.to === id)) rel = true; });
      n.classList.toggle("dim", !rel);
    });
  }
  edgeTip(E) {
    const [col, pl] = PROTO[E.proto] || PROTO.tcp;
    const nm = (id) => (this.nodeEls[id] && this.nodeEls[id]._info.label) || id;
    return `<div class="row-flex"><span class="dot" style="background:${col}"></span><b>${esc(nm(E.from))} ⇄ ${esc(nm(E.to))}</b></div><div class="cell-sub">${esc(E.label || "")}</div><div class="sep"></div>
      <div class="row"><span>${esc(nm(E.from))} → ${esc(nm(E.to))}</span><b>${fmtRate(E.tab)}</b></div>
      <div class="row"><span>${esc(nm(E.to))} → ${esc(nm(E.from))}</span><b>${fmtRate(E.tba)}</b></div>
      <div class="row"><span>Protocole</span><span>${pl}</span></div>${E.conns ? `<div class="row"><span>Connexions</span><span>${E.conns}</span></div>` : ""}
      ${(E.detail || []).length ? `<div class="sep"></div><div class="cell-sub">${E.detail.map(esc).join("<br>")}</div>` : ""}
      ${E.estimated ? '<div class="cell-sub" style="margin-top:6px">Valeur estimée (agrégation de compteurs)</div>' : ""}`;
  }
  nodeTip(id) {
    const n = this.nodeEls[id]; const info = (n && n._info) || {};
    const lv = S.live || {};
    let body = "";
    const m = id === "homelab" ? lv.homelab : id === "nas" ? lv.nas : id === "clawhost" ? (lv.clawhost || {}).metrics : null;
    if (m && m.cpu != null) {
      body = `<div class="row"><span>CPU</span><b>${fmtPct(m.cpu)}</b></div><div class="row"><span>RAM</span><b>${fmtPct(m.mem)}</b></div>
        <div class="row"><span>Charge</span><b>${(m.load || []).map((x) => nf1.format(x)).join(" / ")}</b></div>
        <div class="row"><span>Réseau</span><b>↓${fmtRate(m.rx)} ↑${fmtRate(m.tx)}</b></div><div class="row"><span>Disques</span><b>R ${fmtRate(m.dread)} · W ${fmtRate(m.dwrite)}</b></div>`;
    } else if (id === "clawhost" && lv.clawhost) {
      body = (lv.clawhost.probes || []).map((p) => `<div class="row"><span>${esc(p.name)} :${p.port}</span><b style="color:${p.up ? "var(--ok)" : "var(--crit)"}">${p.up ? (p.ms != null ? nf1.format(p.ms) + " ms" : "OK") : "KO"}</b></div>`).join("");
    }
    let tot = 0; this.edges.forEach((E) => { if (E.from === id || E.to === id) tot += (E.tab || 0) + (E.tba || 0); });
    return `<b>${esc(info.label || id)}</b><div class="cell-sub mono">${esc(info.sub || "")}</div><div class="sep"></div>${body}
      <div class="row"><span>Flux cumulés</span><b>${fmtRate(tot)}</b></div>${HOST_NODES.has(id) && this.opts.onNode ? '<div class="cell-sub" style="margin-top:6px">Clic : détail de la machine</div>' : ""}`;
  }
}
function qpt(p0, c, p2, t) { const u = 1 - t; return [u * u * p0[0] + 2 * u * t * c[0] + t * t * p2[0], u * u * p0[1] + 2 * u * t * c[1] + t * t * p2[1]]; }
function qder(p0, c, p2, t) { return [2 * (1 - t) * (c[0] - p0[0]) + 2 * t * (p2[0] - c[0]), 2 * (1 - t) * (c[1] - p0[1]) + 2 * t * (p2[1] - c[1])]; }

/* ===================================================================== GALAXIE DE CONTENEURS (bulles plates) */
class Galaxy {
  constructor(el) {
    this.el = el; el.innerHTML = `<canvas class="fx"></canvas>`; this.cv = el.querySelector("canvas");
    this.nodes = new Map(); this.clusters = new Map(); this.particles = []; this.hover = null; this.host = "nas";
    this.ro = new ResizeObserver(() => this.resize()); this.ro.observe(el);
    el.addEventListener("mousemove", (e) => this.onMove(e)); el.addEventListener("mouseleave", () => { this.hover = null; hideTip(); });
    ENGINES.add(this); this.resize();
  }
  resize() {
    this.w = this.el.clientWidth; this.h = this.el.clientHeight; this.dpr = Math.min(2, devicePixelRatio || 1);
    this.cv.width = this.w * this.dpr; this.cv.height = this.h * this.dpr; this.layoutClusters();
  }
  setData(list, host) {
    if (host !== this.host) { this.nodes.clear(); this.particles = []; this.host = host; }
    const seen = new Set();
    for (const c of list || []) {
      const key = c.key || c.name;
      seen.add(key);
      let n = this.nodes.get(key);
      const grp = c.project || (c.cat ? "· " + c.cat : "autres");
      if (!n) { n = { name: key, x: this.w / 2 + (Math.random() - 0.5) * 40, y: this.h / 2 + (Math.random() - 0.5) * 40, vx: 0, vy: 0, acc: [0, 0], ph: Math.random() * 6.28 }; this.nodes.set(key, n); }
      Object.assign(n, { c, grp, r: c.r || Math.max(6, Math.min(26, 5 + Math.sqrt((c.mem || 0) / 1e6) * 0.62)), col: c.col || CAT_COLOR[c.cat] || CAT_COLOR.autre });
      n.trx = c.rx || 0; n.ttx = c.tx || 0; n.rx = n.rx ?? 0; n.tx = n.tx ?? 0;
    }
    for (const k of [...this.nodes.keys()]) if (!seen.has(k)) this.nodes.delete(k);
    this.layoutClusters();
  }
  layoutClusters() {
    const groups = {}; this.nodes.forEach((n) => (groups[n.grp] = (groups[n.grp] || 0) + n.r * n.r));
    const keys = Object.keys(groups).sort((a, b) => groups[b] - groups[a]);
    const rx = this.w * 0.38, ry = this.h * 0.36, cx = this.w / 2, cy = this.h / 2;
    this.clusters.clear();
    // un seul projet (cas du homelab) : les bulles forment un anneau autour du cœur plutôt qu'un amas excentré
    this.ringR = keys.length === 1 ? Math.max(70, Math.min(this.w, this.h) * 0.2) : 70;
    if (keys.length === 1) { this.clusters.set(keys[0], { x: cx, y: cy, name: keys[0] }); return; }
    keys.forEach((k, i) => {
      const a = (i / keys.length) * Math.PI * 2 - Math.PI / 2;
      const f = keys.length > 8 && i % 2 ? 0.62 : 1;
      this.clusters.set(k, { x: cx + Math.cos(a) * rx * f, y: cy + Math.sin(a) * ry * f, name: k });
    });
  }
  frame(dt, now) {
    const g = this.cv.getContext("2d"), d = this.dpr, cx = this.w / 2, cy = this.h / 2;
    g.setTransform(1, 0, 0, 1, 0, 0); g.globalCompositeOperation = "source-over"; g.globalAlpha = 1;
    g.clearRect(0, 0, this.cv.width, this.cv.height);
    g.setTransform(d, 0, 0, d, 0, 0);
    const arr = [...this.nodes.values()];
    const hostCol = { nas: "#BF5AF2", lan: "#4A9EFF" }[this.host] || "#64D2FF";
    // physique douce
    for (const n of arr) {
      const cl = this.clusters.get(n.grp) || { x: cx, y: cy };
      n.vx += (cl.x - n.x) * 0.55 * dt + Math.cos(now * 0.6 + n.ph) * 2 * dt;
      n.vy += (cl.y - n.y) * 0.55 * dt + Math.sin(now * 0.5 + n.ph) * 2 * dt;
      const dc = Math.hypot(n.x - cx, n.y - cy), minc = (this.ringR || 70) + n.r;
      if (dc < minc) { const f = 40 + (minc - dc) * 2.5; n.vx += ((n.x - cx) / (dc || 1)) * f * dt; n.vy += ((n.y - cy) / (dc || 1)) * f * dt; }
    }
    for (let i = 0; i < arr.length; i++) for (let j = i + 1; j < arr.length; j++) {
      const a = arr[i], b = arr[j], dx = b.x - a.x, dy = b.y - a.y, dd = Math.hypot(dx, dy) || 0.01, m = a.r + b.r + (this.host === "lan" ? 30 : 12);
      if (dd < m) { const f = ((m - dd) / dd) * 0.5; a.vx -= dx * f * dt * 14; a.vy -= dy * f * dt * 14; b.vx += dx * f * dt * 14; b.vy += dy * f * dt * 14; }
    }
    for (const n of arr) {
      n.vx *= 0.9; n.vy *= 0.9; n.x += n.vx; n.y += n.vy;
      n.x = Math.max(n.r + 4, Math.min(this.w - n.r - 4, n.x)); n.y = Math.max(n.r + 4, Math.min(this.h - n.r - 4, n.y));
      n.rx += (n.trx - n.rx) * Math.min(1, dt * 2); n.tx += (n.ttx - n.tx) * Math.min(1, dt * 2);
    }
    // orbite discrète autour du cœur
    g.setLineDash([2, 6]); g.strokeStyle = "rgba(255,255,255,.07)"; g.lineWidth = 1;
    g.beginPath(); g.arc(cx, cy, (this.ringR || 70) - 6, 0, TAU); g.stroke(); g.setLineDash([]);
    // liens cœur -> amas -> conteneurs (hairlines)
    this.clusters.forEach((cl) => {
      g.strokeStyle = "rgba(255,255,255,.06)"; g.beginPath(); g.moveTo(cx, cy); g.lineTo(cl.x, cl.y); g.stroke();
    });
    for (const n of arr) {
      const cl = this.clusters.get(n.grp); if (!cl) continue;
      g.strokeStyle = withAlpha(n.col, n.c.state === "running" ? 0.2 : 0.07); g.beginPath(); g.moveTo(cl.x, cl.y); g.lineTo(n.x, n.y); g.stroke();
    }
    // points : réseau des conteneurs (réception cyan, émission rose)
    for (const n of arr) {
      [[n.rx, 0], [n.tx, 1]].forEach(([rate, di]) => {
        const I = intensity(rate); if (rate < 30) return;
        n.acc[di] += (0.35 + I * 1.2) * dt * (REDUCED ? 0.3 : 1);
        while (n.acc[di] >= 1) { n.acc[di]--; if (this.particles.length < 500) this.particles.push({ n, di, t: 0, v: 0.32 + I * 0.1, r: 1.4 + Math.min(1.1, I * 0.25) }); }
      });
    }
    const keep = [];
    for (const p of this.particles) {
      p.t += p.v * dt; if (p.t >= 1 || !this.nodes.has(p.n.name)) continue;
      const cl = this.clusters.get(p.n.grp) || { x: cx, y: cy };
      const sg = p.di ? -1 : 1, t = p.di ? 1 - p.t : p.t;
      const P0 = [cx, cy], C = [cl.x, cl.y], P2 = [p.n.x, p.n.y];
      const [x, y] = qpt(P0, C, P2, t), [bx, by] = qpt(P0, C, P2, Math.max(0, Math.min(1, t - sg * 0.05))), [mx, my] = qpt(P0, C, P2, Math.max(0, Math.min(1, t - sg * 0.022)));
      drawDot(g, x, y, bx, by, mx, my, p.r, p.di ? "#FF375F" : "#64D2FF", Math.min(1, p.t * 6, (1 - p.t) * 6) * 0.85, !REDUCED);
      keep.push(p);
    }
    this.particles = keep; g.globalAlpha = 1;
    // cœur (machine) : disque plat teinté
    g.fillStyle = "#1c1c1e"; g.beginPath(); g.arc(cx, cy, 34, 0, TAU); g.fill();
    g.fillStyle = withAlpha(hostCol, 0.14); g.fill();
    g.strokeStyle = withAlpha(hostCol, 0.55); g.lineWidth = 1; g.stroke();
    g.textAlign = "center"; g.fillStyle = "#f5f5f7"; g.font = `600 12.5px ${FX_FONT}`;
    g.fillText({ nas: "NAS", lan: "Box" }[this.host] || "Homelab", cx, cy + 1);
    g.fillStyle = "#98989f"; g.font = `500 10px ${FX_FONT}`;
    g.fillText(`${arr.filter((n) => n.c.state === "running").length} ${this.host === "lan" ? "présents" : "actifs"}`, cx, cy + 15);
    // bulles
    for (const n of arr) {
      const running = n.c.state === "running", cpu = n.c.cpu || 0, hov = this.hover === n.name;
      if (running && cpu > 1) { // halo plat ∝ CPU
        g.fillStyle = withAlpha(n.col, 0.08); g.beginPath(); g.arc(n.x, n.y, n.r + 3 + Math.min(14, cpu / 6), 0, TAU); g.fill();
      }
      g.fillStyle = "#1c1c1e"; g.beginPath(); g.arc(n.x, n.y, n.r, 0, TAU); g.fill();
      g.fillStyle = running ? withAlpha(n.col, 0.2 + Math.min(0.35, cpu / 120)) : "#2c2c2e"; g.fill();
      g.strokeStyle = hov ? "#ffffff" : running ? withAlpha(n.col, 0.8) : "#48484a"; g.lineWidth = hov ? 1.5 : 1; g.stroke();
      if (cpu > 1 && running) { // arc CPU
        g.strokeStyle = cpu > 80 ? "#FF453A" : "rgba(255,255,255,.85)"; g.lineWidth = 1.5; g.lineCap = "round";
        g.beginPath(); g.arc(n.x, n.y, n.r + 3, -Math.PI / 2, -Math.PI / 2 + Math.min(1, cpu / 100) * TAU); g.stroke();
      }
      if (n.r > 15 || hov || cpu > 20 || arr.length <= 16 || n.c.showLabel) {
        g.fillStyle = running ? "#f5f5f7" : "#8e8e93"; g.font = `${hov ? 600 : 500} ${n.c.showLabel && !hov ? 10 : 11}px ${FX_FONT}`; g.textAlign = "center";
        g.fillText((n.c.label || n.name).replace(/^binhex-/, "").slice(0, 18), n.x, n.y + n.r + 14);
      }
    }
    // noms des amas
    g.font = `600 10px ${FX_FONT}`; g.fillStyle = "rgba(152,152,159,.7)"; g.textAlign = "center";
    this.clusters.forEach((cl) => {
      let my = -1e9; this.nodes.forEach((n) => { if (n.grp === cl.name) my = Math.max(my, n.y + n.r); });
      g.fillText(cl.name.toUpperCase(), cl.x, Math.min(this.h - 6, my + 30));
    });
  }
  onMove(e) {
    const r = this.el.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    let hit = null; this.nodes.forEach((n) => { if (Math.hypot(n.x - x, n.y - y) < n.r + 3) hit = n; });
    this.hover = hit && hit.name;
    if (!hit) return hideTip();
    const c = hit.c;
    if (c.tip) return showTip(c.tip, e.clientX, e.clientY);
    showTip(`<b>${esc(c.name)}</b><div class="cell-sub">${esc(c.desc || c.image)}</div><div class="sep"></div>
      <div class="row"><span>État</span><span>${esc(c.status || c.state)}</span></div>
      <div class="row"><span>CPU</span><b>${fmtPct(c.cpu)}</b></div><div class="row"><span>Mémoire</span><b>${fmtBytes(c.mem)}</b></div>
      <div class="row"><span>Réseau ↓ / ↑</span><b>${fmtRate(c.rx)} / ${fmtRate(c.tx)}</b></div>
      <div class="row"><span>Projet</span><span>${esc(c.project || "–")}</span></div><div class="row"><span>Image</span><span class="mono" style="font-size:11px">${esc((c.image || "").slice(0, 38))}</span></div>`, e.clientX, e.clientY);
  }
}

/* ===================================================================== HORLOGE DES TÂCHES (SVG plat) */
function cronClock(el, jobs) {
  const size = 300, c = size / 2, R = 118;
  const now = new Date(), nowS = Date.now() / 1000;
  const ang = (ts) => { const d = new Date(ts * 1000); return ((d.getHours() + d.getMinutes() / 60) / 24) * 360 - 90; };
  const xy = (a, r) => [c + Math.cos((a * Math.PI) / 180) * r, c + Math.sin((a * Math.PI) / 180) * r];
  const f1 = (v) => v.toFixed(1);
  const frequent = jobs.filter((j) => (j.per_day || 0) > 30 && j.enabled);
  let ticks = "";
  const nextJobs = [];
  for (const j of jobs) {
    if ((j.per_day || 0) > 30 || !j.enabled) continue;
    const col = JOB_COLOR[j.cat] || "#8E8E93";
    for (const r of j.runs24 || []) {
      const a = ang(r), soon = r - nowS < 3600;
      const heavy = ["backup", "stockage", "media"].includes(j.cat);
      const [x1, y1] = xy(a, R - (heavy ? 28 : 18)), [x2, y2] = xy(a, R - 6);
      ticks += `<line x1="${f1(x1)}" y1="${f1(y1)}" x2="${f1(x2)}" y2="${f1(y2)}" stroke="${col}" stroke-width="${heavy ? 2.5 : 1.75}" stroke-linecap="round" opacity="${soon ? 1 : 0.78}"
        ${soon ? 'class="soon"' : ""}><title>${esc(fmtTime(r))} · ${esc(HOST_LABEL[j.host])} · ${esc(j.title)}</title></line>`;
      nextJobs.push([r, j]);
    }
  }
  nextJobs.sort((a, b) => a[0] - b[0]);
  const na = ((now.getHours() + now.getMinutes() / 60 + now.getSeconds() / 3600) / 24) * 360 - 90;
  let hours = "";
  for (let h = 0; h < 24; h++) {
    const a = (h / 24) * 360 - 90, [x, y] = xy(a, R + 18), [t1x, t1y] = xy(a, R + 5), [t2x, t2y] = xy(a, R + (h % 6 ? 8 : 11));
    hours += `<line x1="${f1(t1x)}" y1="${f1(t1y)}" x2="${f1(t2x)}" y2="${f1(t2y)}" stroke="rgba(255,255,255,${h % 6 ? 0.16 : 0.32})" stroke-width="1"/>`;
    if (h % 3 === 0) hours += `<text x="${f1(x)}" y="${f1(y + 3.5)}" text-anchor="middle" font-size="10" fill="#8e8e93" style="font-family:var(--mono)">${String(h).padStart(2, "0")}</text>`;
  }
  // heure qui vient (arc de 15° = 1 h) + aiguille courte au bord, le centre reste libre pour le texte
  const [ax, ay] = xy(na, R - 1), [bx, by] = xy(na + 15, R - 1);
  const [h1x, h1y] = xy(na, R - 34), [h2x, h2y] = xy(na, R + 5);
  const nxt = nextJobs[0];
  el.innerHTML = `<svg viewBox="0 0 ${size} ${size}" width="100%" style="max-width:320px">
    <circle cx="${c}" cy="${c}" r="${R}" fill="none" stroke="rgba(255,255,255,.1)" stroke-width="1"/>
    <circle cx="${c}" cy="${c}" r="${R - 36}" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="1" stroke-dasharray="2 5"/>
    ${frequent.length ? `<circle cx="${c}" cy="${c}" r="${R - 42}" fill="none" stroke="#4A9EFF" stroke-opacity=".3" stroke-width="2" stroke-dasharray="1 4"><title>${frequent.length} tâches en continu (≤ 5 min) : ${esc(frequent.map((j) => j.title).join(", "))}</title></circle>` : ""}
    <path d="M ${f1(ax)} ${f1(ay)} A ${R - 1} ${R - 1} 0 0 1 ${f1(bx)} ${f1(by)}" stroke="#4A9EFF" stroke-width="4" fill="none" opacity=".22" stroke-linecap="round"/>
    ${hours}${ticks}
    <line x1="${f1(h1x)}" y1="${f1(h1y)}" x2="${f1(h2x)}" y2="${f1(h2y)}" stroke="#4A9EFF" stroke-width="1.5" stroke-linecap="round"/>
    <circle cx="${f1(h2x)}" cy="${f1(h2y)}" r="3.5" fill="#4A9EFF"/>
    <circle cx="${f1(h2x)}" cy="${f1(h2y)}" r="6.5" fill="none" stroke="#4A9EFF" stroke-opacity=".3" stroke-width="1"/>
  </svg>
  <div class="clock-center">${nxt ? `<div class="k">prochaine</div><div class="n">${esc(nxt[1].title)}</div><div class="c" data-cd="${nxt[0]}">${fmtCountdown(nxt[0] - nowS)}</div><div class="h">${fmtTime(nxt[0])} · ${esc(HOST_LABEL[nxt[1].host])}</div>` : '<div class="k">aucune tâche</div>'}</div>`;
  return nextJobs;
}

/* ===================================================================== PIPELINE DE SAUVEGARDE (SVG plat, tirets qui défilent) */
function backupPipe(el, chains, topo) {
  const W = 1000, H = 330;
  const flowHN = (topo && topo.edges || []).find((e) => e.from === "homelab" && e.to === "nas" && e.proto !== "tailscale");
  const flowCN = (topo && topo.edges || []).find((e) => e.from === "nas" && e.to === "clawhost");
  const active = { homelab: flowHN && flowHN.ab > 200000, clawhost: flowCN && flowCN.ba > 200000 };
  const src = [
    { id: "homelab", y: 60, label: "Homelab", sub: "/opt/homelab", col: "#64D2FF" },
    { id: "clawhost", y: 135, label: "clawhost", sub: "OpenClaw · Netscan · /etc", col: "#FF375F" },
    { id: "forgejo", y: 210, label: "Forgejo", sub: "dépôts Git (NAS)", col: "#A3D977" },
    { id: "appdata", y: 285, label: "Appdata NAS", sub: "bases de toutes les applis", col: "#FF9F0A" },
  ];
  const byId = Object.fromEntries((chains || []).map((c) => [c.id, c]));
  const stCol = (s) => ({ ok: "#30D158", warn: "#FF9F0A", crit: "#FF453A" }[s] || "#8E8E93");
  let paths = "", nodes = "";
  src.forEach((s) => {
    const ch = byId[s.id] || {}; const col = stCol(ch.status);
    const d = `M 210 ${s.y} C 360 ${s.y}, 420 165, 560 165`;
    const dead = ch.status === "crit" && !ch.last_time;
    paths += `<path d="${d}" stroke="${col}" stroke-opacity=".18" stroke-width="1.5" fill="none"/>
      <path d="${d}" stroke="${col}" stroke-opacity="${dead ? 0.45 : 0.85}" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-dasharray="${dead ? "3 7" : "6 12"}" class="${dead ? "" : "flowdash"}" style="${active[s.id] ? "animation-duration:.7s" : ""}"/>`;
    if (!dead) for (let k = 0; k < (active[s.id] ? 3 : 1); k++)
      paths += `<circle r="${active[s.id] ? 3.5 : 3}" fill="${col}"><animateMotion dur="${active[s.id] ? 1.8 : 4.8}s" begin="${k * (active[s.id] ? 0.6 : 1.1)}s" repeatCount="indefinite" path="${d}"/></circle>`;
    nodes += `<g><rect x="20.5" y="${s.y - 25.5}" width="189" height="51" rx="10" fill="#232325" stroke="rgba(255,255,255,.08)"/>
      <rect x="20.5" y="${s.y - 13}" width="2.5" height="26" rx="1.25" fill="${s.col}"/>
      <text x="40" y="${s.y - 3}" fill="#f5f5f7" font-size="14" font-weight="600">${esc(s.label)}</text>
      <text x="40" y="${s.y + 14}" fill="#98989f" font-size="11">${esc(s.sub)}</text>
      <circle cx="190" cy="${s.y}" r="4" fill="${col}">${ch.status === "ok" ? "" : '<animate attributeName="opacity" values="1;.35;1" dur="2s" repeatCount="indefinite"/>'}</circle></g>`;
  });
  const total = (chains || []).reduce((a, c) => a + (c.total || 0), 0);
  el.innerHTML = `<svg class="pipe-svg" viewBox="0 0 ${W} ${H}">
    <style>.flowdash{animation:fd 1.8s linear infinite}@keyframes fd{to{stroke-dashoffset:-36}}.offs{animation:fd 3.2s linear infinite}
      @media (prefers-reduced-motion: reduce){.flowdash,.offs{animation:none}}</style>
    ${paths}${nodes}
    <rect x="560.5" y="95.5" width="189" height="139" rx="14" fill="#232325" stroke="#BF5AF2" stroke-opacity=".45"/>
    <text x="655" y="127" text-anchor="middle" fill="#f5f5f7" font-size="15" font-weight="600">NAS · backups</text>
    <text x="655" y="146" text-anchor="middle" fill="#98989f" font-size="11.5" style="font-family:var(--mono)">//192.168.2.3/backups</text>
    <text x="655" y="181" text-anchor="middle" fill="#f5f5f7" font-size="24" font-weight="600" style="font-variant-numeric:tabular-nums">${fmtBytes(total)}</text>
    <text x="655" y="201" text-anchor="middle" fill="#98989f" font-size="11">gérés par les 4 chaînes</text>
    <text x="655" y="219" text-anchor="middle" fill="#98989f" font-size="11">array 2 parités (P+Q)</text>
    <path d="M 750 165 C 820 165, 830 165, 880 165" stroke="#FF453A" stroke-opacity=".7" stroke-width="1.5" stroke-dasharray="4 7" fill="none" class="offs"/>
    <rect x="880.5" y="125.5" width="104" height="79" rx="12" fill="rgba(255,69,58,.06)" stroke="#FF453A" stroke-opacity=".55" stroke-dasharray="4 4"/>
    <text x="932" y="158" text-anchor="middle" fill="#FF453A" font-size="13" font-weight="600">Hors site</text>
    <text x="932" y="176" text-anchor="middle" fill="#FF6961" font-size="11">aucune copie</text>
    <text x="932" y="192" text-anchor="middle" fill="#98989f" font-size="10.5">règle 3-2-1 ✗</text>
  </svg>`;
}
