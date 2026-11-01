/* InfraDash — « le port » : la vue Docker façon terminal à conteneurs.
   Une machine = un terminal portuaire ; un conteneur Docker = un conteneur maritime (20 ou 40 pieds selon la RAM),
   empilé dans la travée de son projet compose. Activité réelle : ventilateur reefer = CPU, camions = réseau,
   portique = conteneur le plus actif, navire = trafic du terminal. Canvas 2D, rendu plat et sobre.
   API : new Harbor(el, { onSelect(container, host) }) ; setData({ nas, homelab, clawhost }) ; setFilter(q) ; destroy(). */
"use strict";
(function () {
  const FONT = '-apple-system, BlinkMacSystemFont, "Geist", system-ui, "Segoe UI", Roboto, sans-serif';
  // palette sobre : couleurs système Apple, désaturées au rendu (indépendante de CAT_COLOR)
  // (les trois familles les plus nombreuses — applis, bases, infra — sur des teintes bien séparées)
  const PAL = { apps: "#0A84FF", db: "#30D158", infra: "#BF5AF2", download: "#FF9F0A", media: "#FF375F", ia: "#5E5CE6",
    dev: "#64D2FF", securite: "#FF453A", domotique: "#FFD60A", autre: "#8E8E93" };
  const CATS = Object.keys(PAL);
  const CAT_LABEL = { apps: "Applications", db: "Bases de données", media: "Médias", download: "Téléchargement", infra: "Infra",
    ia: "IA", dev: "Dev", securite: "Sécurité", domotique: "Domotique", autre: "Autre" };
  const TERM = {
    nas: { title: "Terminal NAS", sub: "Unraid · 192.168.2.3", ship: "UNRAID EXPRESS", accent: "#0A84FF" },
    homelab: { title: "Terminal Homelab", sub: "Debian · 192.168.2.4", ship: "DEBIAN STAR", accent: "#30D158" },
    clawhost: { title: "Terminal clawhost", sub: "Ubuntu · 192.168.2.5", ship: "CLAW SPIRIT", accent: "#BF5AF2" },
  };
  const HOSTS = Object.keys(TERM);
  const LED = { ok: "#30D158", warn: "#FF9F0A", crit: "#FF453A", off: "#2c2c2e" };
  const PARCEL = { rx: "#5AC8FA", tx: "#FF9F0A" };
  const CRANE = { main: "#b49b55", dark: "#5f5434", light: "#cdbb84", cab: "#d1d1d6", cabTop: "#ececf0" };
  const IN_YARD = new Set(["running", "restarting", "paused"]);
  const SP = 2;   // marge autour des sprites

  /* ---------- utilitaires ---------- */
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const hash = (s) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
  const rng = (seed) => () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const tip = (html, x, y) => { if (typeof showTip === "function") showTip(html, x, y); };
  const untip = () => { if (typeof hideTip === "function") hideTip(); };
  const hexRgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
  function rgbHsl([r, g, b]) {
    r /= 255; g /= 255; b /= 255;
    const mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2;
    let h = 0, s = 0;
    if (mx !== mn) {
      const d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn);
      h = (mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4) / 6;
    }
    return [h, s, l];
  }
  const hsl = (h, s, l, a = 1) => `hsla(${(h * 360).toFixed(1)},${(clamp(s, 0, 1) * 100).toFixed(1)}%,${(clamp(l, 0, 1) * 100).toFixed(1)}%,${a})`;
  // teintes d'un conteneur : face avant, toit, bout (portes), lisses… ; « down » = grisé, un peu rouillé
  const PAINT = {};
  function paint(cat, mode) {
    const k = cat + mode;
    if (PAINT[k]) return PAINT[k];
    const [h, s0, l0] = rgbHsl(hexRgb(PAL[cat] || PAL.autre));
    let s = s0 * 0.46, l = 0.45 + (l0 - 0.55) * 0.3;
    if (mode === "down") { s = 0.07; l = 0.31; }
    return (PAINT[k] = {
      front: hsl(h, s, l), top: hsl(h, s * 0.95, l + 0.085), end: hsl(h, s, l - 0.085), rail: hsl(h, s, l + 0.045),
      post: hsl(h, s, l - 0.055), cast: hsl(h, s * 0.7, l - 0.13), ribL: "rgba(255,255,255,.075)", ribD: "rgba(0,0,0,.12)",
      swatch: hsl(h, s * 1.05, l + 0.06), mini: hsl(h, s * 0.85, l - 0.02), miniTop: hsl(h, s * 0.85, l + 0.06),
    });
  }
  function rr(c, x, y, w, h, r) {   // rectangle arrondi (r : nombre ou [hg, hd, bd, bg])
    const [a, b, d, e] = Array.isArray(r) ? r : [r, r, r, r];
    c.beginPath(); c.moveTo(x + a, y);
    c.arcTo(x + w, y, x + w, y + h, b); c.arcTo(x + w, y + h, x, y + h, d);
    c.arcTo(x, y + h, x, y, e); c.arcTo(x, y, x + w, y, a); c.closePath();
  }
  function spacedW(c, txt, sp) { let w = 0, n = 0; for (const ch of txt) { w += c.measureText(ch).width; n++; } return w + sp * Math.max(0, n - 1); }
  function spaced(c, txt, cx, y, sp) {   // texte centré, lettres espacées (marquage au sol)
    let x = cx - spacedW(c, txt, sp) / 2;
    for (const ch of txt) { c.fillText(ch, x, y); x += c.measureText(ch).width + sp; }
  }
  // nom court sur la plaque : sans le préfixe du projet (déjà peint au sol) ni « binhex- »
  function plateName(name, proj) {
    let n = name.replace(/^binhex-/i, "");
    if (proj) {
      const p = proj.toLowerCase(), low = n.toLowerCase();
      for (const pre of [p, p.split(/[-_]/)[0]]) {
        if (pre && low.startsWith(pre) && /[-_]/.test(low[pre.length] || "") && n.length > pre.length + 1) { n = n.slice(pre.length + 1); break; }
      }
    }
    return n;
  }
  function ledLevel(n) {
    if (!n.up) return "off";
    if (n.state === "restarting") return "blink";
    if (n.state === "paused") return "warn";
    const h = String(n.d.health || "").toLowerCase();
    return h === "unhealthy" ? "crit" : h === "starting" ? "warn" : "ok";
  }
  function stateInfo(n) {
    const d = n.d, h = String(d.health || "").toLowerCase(), pre = n.inv ? "inventaire · " : "";
    if (n.state === "running") {
      if (h === "healthy") return [pre + "en marche · sain", "ok"];
      if (h === "unhealthy") return [pre + "en marche · healthcheck en échec", "crit"];
      if (h === "starting") return [pre + "en marche · démarrage", "warn"];
      return [pre + "en marche", "ok"];
    }
    if (n.state === "restarting") return [pre + "redémarrage en boucle", "warn"];
    if (n.state === "paused") return [pre + "en pause", "warn"];
    if (n.state === "created") return [pre + "créé, jamais démarré", "off"];
    if (n.state === "dead") return [pre + "mort", "crit"];
    const m = /Exited \((\d+)\)/i.exec(d.status || ""), code = m ? m[1] : d.exit;
    return [pre + "arrêté" + (code != null && code !== "" ? ` (code ${code})` : ""), code && code !== "0" ? "crit" : "off"];
  }
  function parsePorts(s) {
    const out = new Set(), re = /(?:\d+\.\d+\.\d+\.\d+|\[::\]):(\d+)->(\d+)\/(\w+)/g;
    let m;
    while ((m = re.exec(s || ""))) out.add(m[1] === m[2] ? `${m[1]}/${m[3]}` : `${m[1]}→${m[2]}/${m[3]}`);
    const a = [...out];
    return a.length > 6 ? a.slice(0, 6).concat(`+${a.length - 6}`) : a;
  }
  // géométrie (px CSS) selon la largeur disponible
  function geom(W, sc) {
    const s = sc || (W >= 1000 ? 1 : W >= 700 ? 0.92 : 0.84), r = (v) => Math.round(v * s);
    const g = { s, L20: r(90), H: r(26), GAP: r(14), AISLE: r(28), DX: r(7), DY: r(7), LANE: r(32), HEAD: r(46), TOP: r(16),
      APRON: r(24), SLAB: r(5), BERTH: r(56), PADX: r(18), CH: r(26), M: r(14) };
    g.L40 = 2 * g.L20 + g.GAP;
    // groupe frigorifique (panneau + ventilateur + voyant) sur la face avant
    g.R = { x: 4 * s, y: 3.5 * s, w: 11 * s, h: g.H - 7 * s, cx: 9.5 * s, cy: g.H / 2 + 2.6 * s, r: 3.2 * s, vy: 7 * s };
    return g;
  }

  class Harbor {
    constructor(el, opts = {}) {
      this.el = el; this.opts = opts || {};
      this.nodes = new Map(); this.seq = new Map(); this.size = new Map(); this.nseq = 0;
      this.T = {}; this.terms = []; this.drawList = []; this.rip = [];
      this.q = ""; this.lcat = null; this.hover = null; this.sel = null; this.mx = 0; this.my = 0;
      this.sprites = new Map(); this.sig = ""; this.W = 0; this.H = 0; this.dpr = 1; this.g = null;
      this.reduced = typeof REDUCED !== "undefined" ? REDUCED : matchMedia("(prefers-reduced-motion: reduce)").matches;
      this.t = 0; this.last = 0; this.dirty = true; this.needLayout = true; this.baseDirty = true; this.inView = true; this.first = true;
      HOSTS.forEach((h) => (this.T[h] = this.newTerm(h)));
      const root = (this.root = document.createElement("div"));
      root.className = "hb-root";
      // deux calques : fond (sol, quais, eau — rafraîchi à 4 Hz) et avant-plan animé (transparent, reçoit la souris)
      this.stage = document.createElement("div");
      this.stage.className = "hb-stage";
      this.bg = document.createElement("canvas");
      this.bg.className = "hb-bg";
      this.bg.setAttribute("aria-hidden", "true");
      this.bgx = this.bg.getContext("2d");
      this.bgT = -1;
      this.cv = document.createElement("canvas");
      this.cv.className = "hb-canvas";
      this.cv.setAttribute("role", "img");
      this.cv.setAttribute("aria-label", "Port à conteneurs : un terminal par machine, un conteneur maritime par conteneur Docker");
      this.ctx = this.cv.getContext("2d");
      this.base = document.createElement("canvas");
      this.bctx = this.base.getContext("2d");
      this.lg = document.createElement("div");
      this.lg.className = "hb-legend";
      this.stage.append(this.bg, this.cv);
      root.append(this.stage, this.lg);
      el.appendChild(root);
      this.buildLegend();
      // interactions
      this._move = (e) => this.onMove(e);
      this._leave = () => { if (this.hover) { this.hover = null; this.dirty = true; untip(); } this.cv.style.cursor = ""; };
      this._click = (e) => this.onClick(e);
      this.cv.addEventListener("pointermove", this._move);
      this.cv.addEventListener("pointerleave", this._leave);
      this.cv.addEventListener("click", this._click);
      // relayout uniquement si la largeur change (la hauteur est la nôtre)
      this.ro = new ResizeObserver(() => { if (Math.round(this.root.clientWidth) !== this.W) { this.needLayout = true; this.dirty = true; } });
      this.ro.observe(el);
      if ("IntersectionObserver" in window) {
        this.io = new IntersectionObserver((es) => { this.inView = es[es.length - 1].isIntersecting; if (this.inView) this.dirty = true; });
        this.io.observe(this.stage);
      }
      // police chargée après coup (Geist) : sprites et textes redessinés
      this._fonts = () => { this.sprites.clear(); this.baseDirty = true; this.terms.forEach((T) => (T.headDirty = true)); this.dirty = true; };
      if (document.fonts) { document.fonts.ready.then(this._fonts); document.fonts.addEventListener("loadingdone", this._fonts); }
      this._frame = (t) => this.frame(t);
      this.raf = requestAnimationFrame(this._frame);
    }

    newTerm(h) {
      return { host: h, ...TERM[h], shelves: [], blocks: [], wait: null, trucks: [], need: 0, st: { tot: 0, run: 0 }, headDirty: true,
        crane: { n: null, x: null, next: 0, hold: 0, hoist: 10, tro: 0, sh: 0 }, ship: { L: 0, f: 0, ph: hash(h) % 7 } };
    }

    /* ---------- données ---------- */
    setData(data) {
      data = data || {};
      // ordre d'arrivée stable : à la première vue, bases de données en bas des piles puis ordre alphabétique
      const fresh = [];
      for (const h of HOSTS) for (const it of data[h] || []) {
        if (it && it.name && !this.seq.has(h + ":" + it.name)) fresh.push([h + ":" + it.name, it]);
      }
      fresh.sort((a, b) => (a[1].cat === "db" ? 0 : 1) - (b[1].cat === "db" ? 0 : 1) || a[0].localeCompare(b[0]));
      fresh.forEach(([k]) => this.seq.set(k, this.nseq++));
      const seen = new Set();
      for (const h of HOSTS) {
        const list = (data[h] || []).filter((it) => it && it.name);
        // inventaire sans projet : regroupement par préfixe commun (netscan-web, netscan-db…)
        const pref = {};
        list.forEach((it) => { if (it.inventory && !it.project) { const p = it.name.split(/[-_]/)[0]; pref[p] = (pref[p] || 0) + 1; } });
        for (const it of list) {
          const key = h + ":" + it.name;
          if (seen.has(key)) continue;
          seen.add(key);
          let n = this.nodes.get(key);
          if (!n) {
            n = { key, host: h, x: 0, y: 0, tx: 0, ty: 0, w: 0, alpha: 0, fa: 1, fta: 1, fan: Math.random() * 6, vph: Math.random() * 6,
              acc: Math.random(), delay: 0, placed: false, trucks: 0, match: true };
            this.nodes.set(key, n);
          }
          n.gone = false; n.d = it; n.name = it.name;
          n.cat = PAL[it.cat] ? it.cat : "autre"; n.inv = !!it.inventory;
          n.state = it.state || (/^up/i.test(it.status || "") ? "running" : "exited");
          n.up = IN_YARD.has(n.state);
          const tok = it.name.split(/[-_]/)[0];
          n.proj = it.project || (n.inv && pref[tok] > 1 ? tok : "");
          n.group = n.proj ? n.proj.toUpperCase() : "AUTONOMES";
          // 20 ou 40 pieds selon la RAM, avec hystérésis pour ne pas faire sauter la disposition
          const m = +it.mem || 0, prev = this.size.get(key);
          let sz = prev || (m >= 500e6 ? 40 : 20);
          if (prev === 40 && m > 0 && m < 440e6) sz = 20; else if (prev === 20 && m >= 560e6) sz = 40;
          this.size.set(key, sz); n.size = sz;
          n.label = plateName(it.name, n.up ? n.proj : "");
          const net = (+it.rx || 0) + (+it.tx || 0);
          n.rate = n.state === "running" && !n.inv ? 0.11 * Math.log10(1 + net / 200) : 0;   // camions / s
          n.score = n.up && !n.inv ? (+it.cpu || 0) + 6 * Math.log10(1 + net / 1000) : 0;
          n.lvl = ledLevel(n);
        }
      }
      for (const n of this.nodes.values()) if (!seen.has(n.key)) n.gone = true;
      // nouvelle disposition seulement si la structure change
      const sig = [...this.nodes.values()].filter((n) => !n.gone).map((n) => `${n.key}|${n.up ? 1 : 0}|${n.size}|${n.group}`).sort().join(";");
      if (sig !== this.sig) { this.sig = sig; this.needLayout = true; }
      this.stats();
      this.legendCounts();
      this.refilter();
      if (this.hover) {
        if (this.hover.gone) { this.hover = null; untip(); } else tip(this.tipHtml(this.hover), this.mx, this.my);
      }
      this.dirty = true;
    }

    stats() {
      for (const h of HOSTS) {
        const T = this.T[h], s = { tot: 0, run: 0, cpu: 0, mem: 0, rx: 0, tx: 0, inv: true };
        for (const n of this.nodes.values()) {
          if (n.host !== h || n.gone) continue;
          s.tot++; if (n.state === "running") s.run++;
          if (!n.inv) s.inv = false;
          if (n.up) { s.cpu += +n.d.cpu || 0; s.mem += +n.d.mem || 0; s.rx += +n.d.rx || 0; s.tx += +n.d.tx || 0; }
        }
        T.st = s; T.headDirty = true;
      }
    }

    matches(n) {
      if (this.lcat) return n.cat === this.lcat;
      if (!this.q) return true;
      const d = n.d;
      return [d.name, d.image, d.project, n.proj, n.cat, CAT_LABEL[n.cat], d.desc, n.host].join(" ").toLowerCase().includes(this.q);
    }
    refilter() {
      const any = !!(this.q || this.lcat);
      for (const n of this.nodes.values()) { n.match = this.matches(n); n.fta = !any || n.match ? 1 : 0.14; }
      this.dirty = true;
    }
    setFilter(q) {
      const v = String(q || "").trim().toLowerCase();
      if (v === this.q) return;
      this.q = v;
      this.refilter();
    }

    /* ---------- disposition ---------- */
    layout() {
      this.needLayout = false;
      const W = Math.round(this.root.clientWidth || this.el.clientWidth);
      if (!W) return;
      this.W = W;
      this.dpr = Math.min(2, window.devicePixelRatio || 1);
      const live = (h) => [...this.nodes.values()].filter((n) => n.host === h && !n.gone);
      const terms = HOSTS.filter((h) => live(h).length).map((h) => this.T[h]);
      // nœuds d'un terminal qui disparaît : retirés sans transition
      for (const n of this.nodes.values()) if (n.gone && !terms.includes(this.T[n.host])) this.nodes.delete(n.key);
      let g = (this.g = geom(W));
      terms.forEach((T) => this.blocks(T, live(T.host), W));
      // agencement : le plus grand terminal à gauche, les autres en colonne à droite ; empilés sur mobile
      const place = (T, x, y, w) => this.placeTerm(T, x, y, w);
      const width1 = (T) => T.need + 2 * this.g.PADX + this.g.DX;
      let A = W - 2 * g.M, Hc = 160;
      if (terms.length && (W < 700 || terms.length === 1)) {
        let y = g.M;
        terms.forEach((T) => { y += place(T, g.M, y, A) + g.CH; });
        Hc = y - g.CH - g.M;
      } else if (terms.length) {
        const big = terms.reduce((a, b) => (b.need > a.need ? b : a)), rest = terms.filter((t) => t !== big);
        if (W >= 1150) {
          // petite recherche : largeur de la colonne de droite × échelle, pour la hauteur totale la plus faible ;
          // refaite seulement si la largeur ou la liste des terminaux change (sinon la disposition reste stable)
          const run = (rw) => {
            const G = this.g, lw = A - rw - G.CH, hl = place(big, G.M, G.M, lw);
            let yr = G.M;
            rest.forEach((T) => { yr += place(T, G.M + lw + G.CH, yr, rw) + G.CH; });
            return Math.max(hl, yr - G.CH - G.M);
          };
          const split = () => terms.reduce((a, T) => a + T.parts, 0);   // travées coupées : pénalisées (moins lisibles)
          const hk = W + "|" + terms.map((t) => t.host).join(",");
          let best = this.arr && this.arr.k === hk ? this.arr : null;
          if (!best) for (const sc of [1, 0.93]) {
            g = this.g = geom(W, sc); A = W - 2 * g.M;
            terms.forEach((T) => this.blocks(T, live(T.host), W));
            const cand = new Set(rest.map(width1));
            for (let f = 0.22; f <= 0.445; f += 0.02) cand.add(Math.round(A * f));
            for (const rw of cand) {
              if (rw < A * 0.2 || rw > A * 0.46) continue;
              const h = run(rw) * (sc < 1 ? 1.08 : 1) + split() * 24;   // la petite échelle doit vraiment faire gagner de la place
              if (!best || h < best.h - 1 || (Math.abs(h - best.h) <= 1 && rw > best.rw)) best = { h, sc, rw };
            }
          }
          this.arr = { k: hk, sc: best.sc, rw: best.rw };
          g = this.g = geom(W, best.sc); A = W - 2 * g.M;
          terms.forEach((T) => this.blocks(T, live(T.host), W));
          Hc = run(best.rw);
        } else {
          let y = g.M + place(big, g.M, g.M, A) + g.CH;
          const need = rest.reduce((a, t) => a + width1(t), 0) + g.CH * (rest.length - 1);
          if (need <= A) {
            let x = g.M, hm = 0;
            const extra = (A - need) / rest.length;
            rest.forEach((T) => { const w = width1(T) + extra; hm = Math.max(hm, place(T, x, y, w)); x += w + g.CH; });
            y += hm + g.CH;
          } else rest.forEach((T) => { y += place(T, g.M, y, A) + g.CH; });
          Hc = y - g.CH - g.M;
        }
      }
      this.terms = terms;
      this.H = Math.ceil(Hc + 2 * g.M);
      const cw = Math.round(W * this.dpr), ch = Math.round(this.H * this.dpr);
      for (const cv of [this.cv, this.bg, this.base]) if (cv.width !== cw || cv.height !== ch) { cv.width = cw; cv.height = ch; }
      this.stage.style.height = this.H + "px";
      // cibles des nœuds ; les nouveaux descendent du ciel (déposés par le portique)
      const firstLoad = this.first;
      terms.forEach((T, ti) => T.shelves.forEach((sh) => sh.nodes.forEach((n) => {
        if (n.placed) return;
        n.placed = true; n.x = n.tx; n.y = n.ty - 34 * g.s; n.alpha = 0;
        if (firstLoad) n.delay = 0.1 + ti * 0.15 + ((n.tx - T.x) / W) * 0.7 + ((sh.g - n.ty) / g.H) * 0.06;
        else if (n.up) { T.crane.n = n; T.crane.hold = this.t + 6; }
      })));
      if (terms.length) this.first = false;
      // mémorise la rangée et le rang de chaque travée : la prochaine disposition (même largeur) les conserve
      terms.forEach((T) => {
        T.assign = new Map();
        T.shelves.forEach((sh, j) => sh.blocks.forEach((b, i) => T.assign.set(b.id, { sh: j, i })));
        T.assignKey = `${Math.round(T.w)}|${g.s}`;
      });
      terms.forEach((T) => { T.trucks.forEach((tr) => (tr.n.trucks = 0)); T.trucks = []; T.crane.next = 0; T.headDirty = true; });
      this.makeRipples();
      this.baseDirty = true;
      this.dirty = true;
      if (this.reduced) this.snap();
    }

    // travées (un bloc par projet), piles de 3-4 max, 40 pieds d'un côté, 20 pieds de l'autre
    blocks(T, ns, W) {
      const g = this.g, bySeq = (a, b) => this.seq.get(a.key) - this.seq.get(b.key);
      const yard = ns.filter((n) => n.up).sort(bySeq), wait = ns.filter((n) => !n.up).sort(bySeq);
      const m = yard.length > 24 ? 4 : 3, groups = new Map();
      const narrow = W < 700 ? W - 2 * g.M - 2 * g.PADX - g.DX : 1e9;   // sur mobile : piles de 4 plutôt qu'une travée coupée en deux
      yard.forEach((n) => { if (!groups.has(n.group)) groups.set(n.group, []); groups.get(n.group).push(n); });
      T.blocks = [...groups].map(([label, arr]) => {
        const b = this.mkBlock(label, arr, m, false);
        return b.w > narrow && m < 4 ? this.mkBlock(label, arr, 4, false) : b;
      });
      T.wait = wait.length ? this.mkBlock("ZONE D'ATTENTE", wait, 2, true) : null;
      const all = T.blocks.concat(T.wait ? [T.wait] : []);
      T.need = all.reduce((a, b) => a + b.w, 0) + g.AISLE * Math.max(0, all.length - 1);
    }
    mkBlock(label, arr, m, wait) {
      const g = this.g, stacks = [];
      for (const sz of [40, 20]) {
        const list = arr.filter((n) => (n.size === 40) === (sz === 40));
        if (!list.length) continue;
        const k = Math.ceil(list.length / m), st = [];
        for (let i = 0; i < k; i++) st.push({ size: sz, w: sz === 40 ? g.L40 : g.L20, items: [], x: 0, g: 0 });
        list.forEach((n, i) => st[i % k].items.push(n));   // répartition équilibrée, stable tant que le nombre de piles ne change pas
        stacks.push(...st);
      }
      return { label, wait, stacks, inv: arr.every((n) => n.inv), w: stacks.reduce((a, s) => a + s.w, 0) + g.GAP * (stacks.length - 1) };
    }
    placeTerm(T, x, y, w) {
      const g = this.g, s = g.s;
      T.x = x; T.y = y; T.w = w;
      const inner = w - 2 * g.PADX - g.DX;
      const split = (b) => {   // travée trop large pour la rangée : coupée en plusieurs tronçons
        if (b.w <= inner) return [b];
        const out = [];
        let cur = [], cw = 0;
        for (const st of b.stacks) {
          if (cur.length && cw + g.GAP + st.w > inner) { out.push(cur); cur = []; cw = 0; }
          cw += (cur.length ? g.GAP : 0) + st.w; cur.push(st);
        }
        if (cur.length) out.push(cur);
        return out.map((sts) => ({ ...b, part: true, stacks: sts, w: sts.reduce((a, st) => a + st.w, 0) + g.GAP * (sts.length - 1) }));
      };
      // rangées : nombre minimal par premier ajustement décroissant, puis répartition équilibrée (plus petite rangée d'abord) ;
      // déterministe, donc stable tant que la composition ne change pas
      const raw = T.blocks.flatMap(split).concat(T.wait ? split(T.wait) : []), seen = {};
      raw.forEach((b) => { seen[b.label] = (seen[b.label] || 0) + 1; b.id = b.label + "#" + (seen[b.label] - 1); });
      const blocks = [...raw].sort((a, b) => b.w - a.w || (a.wait ? 1 : 0) - (b.wait ? 1 : 0) || a.label.localeCompare(b.label));
      const fits = (sh, b) => sh.used + (sh.blocks.length ? g.AISLE : 0) + b.w <= inner;
      const put = (sh, b) => { sh.used += (sh.blocks.length ? g.AISLE : 0) + b.w; sh.blocks.push(b); };
      const sticky = T.assign && T.assignKey === `${Math.round(w)}|${g.s}` ? T.assign : null;
      let shelves = [];
      if (sticky) {   // même largeur : chaque travée garde sa rangée ; les nouvelles vont dans la rangée la moins remplie
        const K = Math.max(0, ...[...sticky.values()].map((a) => a.sh)) + 1;
        shelves = Array.from({ length: K }, () => ({ blocks: [], used: 0 }));
        const known = raw.filter((b) => sticky.has(b.id)).sort((a, b) => sticky.get(a.id).sh - sticky.get(b.id).sh || sticky.get(a.id).i - sticky.get(b.id).i);
        const fresh = raw.filter((b) => !sticky.has(b.id));
        for (const b of known) { const sh = shelves[sticky.get(b.id).sh]; if (fits(sh, b)) put(sh, b); else fresh.push(b); }
        for (const b of fresh.sort((a, b) => b.w - a.w)) {
          let sh = shelves.filter((x) => fits(x, b)).sort((a, c) => a.used - c.used)[0];
          if (!sh) shelves.push((sh = { blocks: [], used: 0 }));
          put(sh, b);
        }
        shelves = shelves.filter((sh) => sh.blocks.length);
      } else for (const b of blocks) { let sh = shelves.find((x) => fits(x, b)); if (!sh) shelves.push((sh = { blocks: [], used: 0 })); put(sh, b); }
      if (!sticky && shelves.length > 1) {
        const bal = Array.from({ length: shelves.length }, () => ({ blocks: [], used: 0 }));
        let ok = true, k = 0;
        const parts = raw.filter((b) => b.part);   // tronçons d'une travée coupée : rangées consécutives, dans l'ordre
        for (const b of parts) { if (fits(bal[k % bal.length], b)) put(bal[k % bal.length], b); else ok = false; k++; }
        for (const b of blocks) {
          if (b.part) continue;
          const sh = bal.filter((x) => fits(x, b)).sort((a, c) => a.used - c.used)[0];
          if (!sh) { ok = false; break; }
          put(sh, b);
        }
        if (ok) shelves = bal;
      }
      // dans chaque rangée : ordre précédent conservé, sinon les plus larges d'abord (la zone d'attente reste calée à droite)
      const rank = (b) => (sticky && sticky.has(b.id) ? sticky.get(b.id).i : 1e6 - b.w);
      shelves.forEach((sh) => sh.blocks.sort((a, b) => (a.wait ? 1 : 0) - (b.wait ? 1 : 0) || rank(a) - rank(b) || a.label.localeCompare(b.label)));
      let cy = y + g.HEAD;
      shelves.forEach((sh, j) => {
        sh.lv = Math.max(1, ...sh.blocks.flatMap((b) => b.stacks.map((st) => st.items.length)));
        sh.top = cy; sh.g = cy + g.TOP + g.DY + sh.lv * g.H; cy = sh.g + g.LANE;
        // allées élargies si la rangée est presque pleine ; zone d'attente calée à droite
        const main = sh.blocks.filter((b) => !b.wait), wt = sh.blocks.filter((b) => b.wait);
        const wW = wt.reduce((a, b) => a + b.w + g.AISLE, 0);
        const used = main.reduce((a, b) => a + b.w, 0) + g.AISLE * Math.max(0, main.length - 1);
        const slack = inner - wW - used;
        const add = main.length < 2 ? 0 : slack < inner * 0.35 ? Math.min(slack / (main.length - 1), 90 * s) : Math.min(slack / (main.length - 1), 40 * s);
        let bx = x + g.PADX;
        main.forEach((b) => { b.x = bx; bx += b.w + g.AISLE + add; });
        let wx = x + g.PADX + inner;
        for (let i = wt.length - 1; i >= 0; i--) { wx -= wt[i].w; wt[i].x = wx; wx -= g.AISLE; }
        sh.nodes = [];
        for (const b of sh.blocks) {
          let sx = b.x;
          for (const st of b.stacks) {
            st.x = sx; st.g = sh.g;
            st.items.forEach((n, lv) => { n.tx = sx; n.ty = sh.g - (lv + 1) * g.H; n.w = st.w; n.stack = st; n.shelf = j; n.T = T; sh.nodes.push(n); });
            sx += st.w + g.GAP;
          }
        }
        // allées libres de la rangée (passages des camions vers les rangées du fond)
        const bs = [...sh.blocks].sort((a, b) => a.x - b.x);
        sh.free = [];
        let cur = x + 6 * s;
        for (const b of bs) { if (b.x - cur >= 12 * s) sh.free.push([cur, b.x - 2 * s]); cur = b.x + b.w + g.DX + 2 * s; }
        if (x + w - 6 * s - cur >= 12 * s) sh.free.push([cur, x + w - 6 * s]);
      });
      T.shelves = shelves;
      T.parts = raw.filter((b) => b.part).length - new Set(raw.filter((b) => b.part).map((b) => b.label)).size;
      T.edge = cy + g.APRON; T.apronY = cy + g.APRON * 0.55; T.berth = T.edge + g.SLAB;
      T.h = T.berth + g.BERTH - y;
      return T.h;
    }

    makeRipples() {
      const g = this.g, R = rng(11), W = this.W, H = this.H, out = [];
      const land = this.terms.map((T) => [T.x - 16 * g.s, T.y - 6, T.w + 22 * g.s, T.berth - T.y + 10]);
      const n = Math.round((W * H) / 2300);
      for (let i = 0; i < n && out.length < 280; i++) {
        const x = R() * W, y = R() * H;
        if (land.some(([a, b, w, h]) => x > a && x < a + w && y > b && y < b + h)) continue;
        out.push({ x, y, l: (5 + R() * 10) * g.s, ph: R() * 6.283, sp: 0.25 + R() * 0.5 });
      }
      this.rip = out;
    }

    /* ---------- boucle ---------- */
    frame(ts) {
      this.raf = requestAnimationFrame(this._frame);
      if (this.el.offsetParent === null || document.hidden) { this.last = 0; return; }   // vue masquée : pause
      if (this.needLayout) this.layout();
      if (!this.g || !this.inView) { this.last = 0; return; }
      const dt = this.last ? Math.min(0.05, (ts - this.last) / 1000) : 1 / 60;
      this.last = ts;
      if (this.reduced) {   // mouvement réduit : rendu à la demande, sans animation
        if (!this.dirty) return;
        this.snap(); this.draw(); this.dirty = false;
        return;
      }
      this.t += dt;
      this.update(dt);
      this.draw();
    }
    snap() {
      for (const n of this.nodes.values()) { n.x = n.tx; n.y = n.ty; n.alpha = n.gone ? 0 : 1; n.fa = n.fta; n.delay = 0; if (n.gone) this.nodes.delete(n.key); }
      for (const T of this.terms) { this.craneTick(T, 0, true); this.shipTick(T, 0, true); }
    }
    update(dt) {
      const g = this.g, k = 1 - Math.exp(-dt * 6.5), kf = 1 - Math.exp(-dt * 8), ka = Math.min(1, dt * 4.5);
      for (const n of this.nodes.values()) {
        if (n.delay > 0) { n.delay -= dt; continue; }
        if (n.gone) { n.y -= 26 * g.s * dt; n.alpha = Math.max(0, n.alpha - dt * 1.8); if (n.alpha <= 0) this.nodes.delete(n.key); continue; }
        n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k;
        n.alpha += (1 - n.alpha) * ka; n.fa += (n.fta - n.fa) * kf;
        if (n.up && !n.inv) {
          const cpu = Math.min(+n.d.cpu || 0, 400);
          n.fan += dt * Math.min(24, cpu * 0.2);             // ventilateur ∝ CPU
          n.vph += dt * (0.5 + Math.min(cpu, 200) * 0.03) * 6.283;
        }
        if (n.rate > 0 && n.T) { n.acc += dt * n.rate; if (n.acc >= 1) { n.acc -= 1; this.spawn(n); } }
      }
      for (const T of this.terms) {
        for (let i = T.trucks.length - 1; i >= 0; i--) if (this.truckTick(T, T.trucks[i], dt)) { T.trucks[i].n.trucks--; T.trucks.splice(i, 1); }
        this.craneTick(T, dt);
        this.shipTick(T, dt);
      }
    }

    /* ---------- camions (réseau) ---------- */
    spawn(n) {
      const T = n.T;
      if (!T || !T.shelves.length || T.trucks.length >= 26 || n.trucks >= 4 || !n.stack) return;
      const pts = this.path(T, n), seg = [0];
      for (let i = 1; i < pts.length; i++) seg.push(seg[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
      const rx = +n.d.rx || 0, tx = +n.d.tx || 0, tot = rx + tx || 1;
      T.trucks.push({ n, pts, seg, L: seg[seg.length - 1], d: 0, ph: 0, wait: 0, pin: rx / tot >= 0.15, pout: tx / tot >= 0.15,
        x: pts[0][0], y: pts[0][1], hx: 0, hy: -1, ox: 0, oy: 0, band: T.shelves.length });
      n.trucks++;
    }
    // itinéraire : du quai (près du navire) jusqu'à la voie devant le conteneur, en passant par les allées libres
    path(T, n) {
      const g = this.g, sh = T.shelves, k = n.shelf, cx = n.stack.x + n.stack.w / 2;
      const L = T.ship.L || 200, sx = T.x + (T.w - L) / 2;
      const x0 = clamp(cx, sx + 14 * g.s, sx + L - 14 * g.s);
      const pts = [[x0, T.apronY]];
      let x = x0, y = T.apronY;
      const best = (free) => {
        let bx = x, bc = 1e9;
        for (const [a, b] of free) {
          const p = b - a < 44 * g.s ? (a + b) / 2 : clamp(cx, a + 10 * g.s, b - 10 * g.s);
          const c = Math.abs(p - x) + Math.abs(cx - p) + Math.abs(cx - p) * 0.01;
          if (c < bc) { bc = c; bx = p; }
        }
        return bx;
      };
      for (let j = sh.length - 1; j > k; j--) {
        const ax = best(sh[j].free);
        if (Math.abs(ax - x) > 0.5) pts.push([ax, y]);
        y = sh[j - 1].g + g.LANE * 0.62; pts.push([ax, y]); x = ax;
      }
      const ly = sh[k].g + g.LANE * 0.62;
      if (y !== ly) { if (Math.abs(cx - x) > 0.5) pts.push([cx, y]); pts.push([cx, ly]); }
      else if (Math.abs(cx - x) > 0.5) pts.push([cx, ly]);
      return pts;
    }
    truckTick(T, tr, dt) {
      const g = this.g, v = 130 * g.s, ease = () => Math.min(1, 0.3 + Math.min(tr.d, tr.L - tr.d) / (22 * g.s));
      if (tr.ph === 0) { tr.d = Math.min(tr.L, tr.d + v * dt * ease()); if (tr.d >= tr.L - 0.01) { tr.ph = 1; tr.wait = 0.9; } }
      else if (tr.ph === 1) { tr.wait -= dt; if (tr.wait <= 0) tr.ph = 2; }
      else { tr.d = Math.max(0, tr.d - v * dt * ease()); if (tr.d <= 0.01) return true; }
      let i = 1;
      while (i < tr.seg.length - 1 && tr.seg[i] < tr.d) i++;
      const a = tr.pts[i - 1], b = tr.pts[i] || a, sl = tr.seg[i] - tr.seg[i - 1] || 1, f = (tr.d - tr.seg[i - 1]) / sl;
      if (tr.ph !== 1) { const s = tr.ph === 2 ? -1 : 1; tr.hx = ((b[0] - a[0]) / sl) * s; tr.hy = ((b[1] - a[1]) / sl) * s; }
      // on roule à droite : décalage perpendiculaire lissé dans les virages
      const off = 3.4 * g.s, kk = Math.min(1, dt * 12);
      tr.ox += (-tr.hy * off - tr.ox) * kk; tr.oy += (tr.hx * off - tr.oy) * kk;
      tr.x = a[0] + (b[0] - a[0]) * f + tr.ox; tr.y = a[1] + (b[1] - a[1]) * f + tr.oy;
      let band = T.shelves.length;
      for (let j = 0; j < T.shelves.length; j++) if (tr.y <= T.shelves[j].g + g.LANE) { band = j; break; }
      tr.band = band;
      return false;
    }

    /* ---------- portique (conteneur le plus actif) ---------- */
    craneTarget(T) {
      const k = T.crane, ns = [];
      T.shelves.forEach((sh) => sh.nodes.forEach((n) => { if (!n.gone && n.up) ns.push(n); }));
      if (!ns.length) { T.shelves.forEach((sh) => sh.nodes.forEach((n) => { if (!n.gone) ns.push(n); })); }
      if (!ns.length) { k.n = null; return; }
      if (k.n && (k.n.gone || !ns.includes(k.n))) k.n = null;
      const rs = ns.find((n) => n.state === "restarting");   // un conteneur qui redémarre : le portique va au-dessus
      if (rs) { k.n = rs; return; }
      if (k.n && this.t < k.hold) return;
      const best = ns.reduce((a, b) => (b.score > a.score ? b : a));
      if (!k.n || (best !== k.n && best.score > k.n.score * 1.3 + 1.5)) { k.n = best; k.hold = this.t + 8; }
    }
    craneTick(T, dt, snap) {
      const k = T.crane, g = this.g;
      if (snap || this.t >= k.next) { k.next = this.t + 1.2; this.craneTarget(T); }
      const n = k.n;
      if (!n || !n.stack || !T.shelves[n.shelf]) return;
      const st = n.stack, sh = T.shelves[n.shelf];
      const tg = { x: st.x + st.w / 2, gy: sh.g, lv: sh.lv, hw: st.w / 2 + 11 * g.s, sw: st.w + 4 * g.s, top: st.g - st.items.length * g.H };
      if (k.x == null || snap) Object.assign(k, tg);
      else {
        const a = 1 - Math.exp(-dt * 1.4), lim = 85 * g.s * dt;
        k.x += clamp((tg.x - k.x) * a, -lim, lim);
        for (const p of ["gy", "lv", "hw", "sw", "top"]) k[p] += (tg[p] - k[p]) * a;
      }
      k.moving = Math.abs(tg.x - k.x) > 3 * g.s || Math.abs(tg.gy - k.gy) > 3 * g.s;
      const ht = snap ? 6 * g.s : k.moving ? 15 * g.s : (3.5 + 3.5 * Math.sin(this.t * 0.8)) * g.s;
      k.hoist += snap ? ht - k.hoist : (ht - k.hoist) * (1 - Math.exp(-dt * 2.2));
      k.tro = snap ? 0 : Math.sin(this.t * 0.45) * 3 * g.s;
      let bj = 0, bd = 1e9;
      T.shelves.forEach((s2, j) => { const d = Math.abs(s2.g - k.gy); if (d < bd) { bd = d; bj = j; } });
      k.sh = bj;
    }

    /* ---------- navire (trafic du terminal) ---------- */
    shipTick(T, dt, snap) {
      const g = this.g, sh = T.ship, tot = (T.st.rx || 0) + (T.st.tx || 0);
      const f = clamp(Math.log10(1 + tot / 1000) / 4.2, 0, 1);
      const bw = T.w - 2 * g.PADX - 30 * g.s;
      const L = Math.min(bw, clamp(bw * (0.3 + 0.42 * f), 120 * g.s, 560 * g.s));
      if (snap || !sh.L) { sh.L = L; sh.f = f; return; }
      const a = 1 - Math.exp(-dt * 1.2);
      sh.L += (L - sh.L) * a; sh.f += (f - sh.f) * a;
    }

    /* ---------- rendu ---------- */
    draw() {
      const c = this.ctx;
      if (this.baseDirty) { this.drawBase(); this.bgT = -1; }
      if (this.bgT < 0 || this.t - this.bgT >= 0.25) this.drawBg();
      c.setTransform(1, 0, 0, 1, 0, 0);
      c.clearRect(0, 0, this.cv.width, this.cv.height);
      c.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      this.drawList = [];
      const hl = !!(this.q || this.lcat);
      for (const T of this.terms) {
        if (T.headDirty) { this.fitHead(T); T.headDirty = false; }
        this.drawShip(c, T);
        const K = T.shelves.length, k = T.crane;
        for (let j = 0; j < K; j++) {
          const here = k.n && k.x != null && k.sh === j;
          if (here) this.drawCrane(c, T, false);
          this.drawShelf(c, T.shelves[j].nodes, hl);
          if (here) this.drawCrane(c, T, true);
          for (const tr of T.trucks) if (tr.band === j) this.drawTruck(c, tr);
        }
        for (const tr of T.trucks) if (tr.band >= K) this.drawTruck(c, tr);
        this.drawHead(c, T);
      }
      for (const n of this.nodes.values()) if (n.gone) this.drawNode(c, n, false);
      const sel = this.sel && this.nodes.get(this.sel);
      for (const n of [sel, this.hover]) {
        if (!n || n.gone || n.alpha < 0.1) continue;
        this.outline(c, n); c.strokeStyle = "#fff"; c.lineWidth = 1.5; c.stroke();
      }
    }

    drawBg() {   // fond : sol et quais (statiques) + vaguelettes très lentes
      this.bgT = this.t;
      const b = this.bgx;
      b.setTransform(1, 0, 0, 1, 0, 0);
      b.drawImage(this.base, 0, 0);
      if (this.rip.length) { b.setTransform(this.dpr, 0, 0, this.dpr, 0, 0); this.drawRipples(b); }
    }

    drawBase() {
      this.baseDirty = false;
      const b = this.bctx, g = this.g, s = g.s, W = this.W, H = this.H;
      b.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      const wg = b.createLinearGradient(0, 0, 0, H);
      wg.addColorStop(0, "#0b1620"); wg.addColorStop(1, "#0f2233");
      b.fillStyle = wg; b.fillRect(0, 0, W, H);
      b.textBaseline = "middle"; b.textAlign = "left";
      if (!this.terms.length) {
        b.fillStyle = "#8e8e93"; b.font = `500 ${13 * s}px ${FONT}`; b.textAlign = "center";
        b.fillText("Aucun conteneur à afficher", W / 2, H / 2);
        return;
      }
      for (const T of this.terms) {
        const L = T.x, R = T.x + T.w, edge = T.edge;
        b.fillStyle = "rgba(0,0,0,.32)"; b.fillRect(L + 6 * s, edge + g.SLAB, T.w - 6 * s, 4 * s);   // ombre portée, plate
        rr(b, L, T.y, T.w, edge - T.y, [12 * s, 12 * s, 0, 0]);
        b.fillStyle = "#1c1c1e"; b.fill();
        b.strokeStyle = "rgba(255,255,255,.05)"; b.lineWidth = 1; b.stroke();
        b.fillStyle = "#111113"; b.fillRect(L, edge, T.w, g.SLAB);                                // mur de quai
        for (const sh of T.shelves) {
          // voie de circulation (asphalte + pointillés)
          b.fillStyle = "#171719"; b.fillRect(L + 6 * s, sh.g, T.w - 12 * s, g.LANE);
          b.strokeStyle = "rgba(255,255,255,.07)"; b.lineWidth = 1; b.setLineDash([7 * s, 7 * s]);
          b.beginPath(); b.moveTo(L + 10 * s, Math.round(sh.g + g.LANE * 0.62) + 0.5); b.lineTo(R - 10 * s, Math.round(sh.g + g.LANE * 0.62) + 0.5); b.stroke();
          b.setLineDash([]);
          for (const bk of sh.blocks) {
            const x0 = bk.x, x1 = bk.x + bk.w;
            if (bk.wait) {   // zone d'attente hachurée
              const zy = sh.top + g.TOP * 0.45, zh = sh.g - zy, zx = x0 - 6 * s, zw = x1 + g.DX + 6 * s - zx;
              b.save(); b.beginPath(); b.rect(zx, zy, zw, zh); b.clip();
              b.strokeStyle = "rgba(255,159,10,.075)"; b.lineWidth = 3 * s; b.beginPath();
              for (let k = zx - zh; k < zx + zw; k += 10 * s) { b.moveTo(k, zy + zh); b.lineTo(k + zh, zy); }
              b.stroke(); b.restore();
              b.strokeStyle = "rgba(255,159,10,.32)"; b.lineWidth = 1; b.setLineDash([4 * s, 3 * s]);
              b.strokeRect(Math.round(zx) + 0.5, Math.round(zy) + 0.5, Math.round(zw) - 1, Math.round(zh)); b.setLineDash([]);
            }
            // marquage au sol : ligne de travée + repères d'emplacement
            b.fillStyle = bk.wait ? "rgba(255,159,10,.4)" : "rgba(255,214,10,.28)";
            b.fillRect(x0, sh.g + 2 * s, x1 - x0, 1.5 * s);
            for (const st of bk.stacks) { b.fillRect(st.x, sh.g + 2 * s, 1.3 * s, 4.5 * s); b.fillRect(st.x + st.w - 1.3 * s, sh.g + 2 * s, 1.3 * s, 4.5 * s); }
            // nom de la travée, peint au sol
            let txt = bk.label + (bk.inv && !bk.wait ? " · INVENTAIRE" : "");
            const avail = bk.w + g.AISLE * 0.75;
            let fs = 9.5 * s, sp = 1.6 * s;
            b.font = `650 ${fs}px ${FONT}`;
            if (spacedW(b, txt, sp) > avail && bk.inv) { txt = bk.label; }
            while (spacedW(b, txt, sp) > avail && (sp > 0.6 * s || fs > 7.5 * s)) {
              if (sp > 0.6 * s) sp -= 0.25 * s; else fs -= 0.5 * s;
              b.font = `650 ${fs}px ${FONT}`;
            }
            if (spacedW(b, txt, sp) > avail) {
              while (txt.length > 3 && spacedW(b, txt + "…", sp) > avail) txt = txt.slice(0, -1);
              txt += "…";
            }
            b.fillStyle = bk.wait ? "rgba(255,159,10,.7)" : "rgba(235,235,245,.42)";
            spaced(b, txt, (x0 + x1) / 2, sh.g + 12.5 * s, sp);
          }
        }
        // quai : tablier, ligne de sécurité, arête, bollards
        b.fillStyle = "#222224"; b.fillRect(L, edge - g.APRON, T.w, g.APRON);
        b.strokeStyle = "rgba(255,214,10,.28)"; b.lineWidth = 1.2 * s; b.setLineDash([10 * s, 6 * s]);
        b.beginPath(); b.moveTo(L + 8 * s, edge - g.APRON + 3.5 * s); b.lineTo(R - 8 * s, edge - g.APRON + 3.5 * s); b.stroke(); b.setLineDash([]);
        b.fillStyle = "rgba(255,255,255,.11)"; b.fillRect(L, edge - 1.5 * s, T.w, 1.5 * s);
        b.fillStyle = "#3a3a3c";
        for (let x = L + 22 * s; x < R - 10 * s; x += 58 * s) { b.beginPath(); b.arc(x, edge - 5 * s, 2.2 * s, 0, 6.283); b.fill(); }
      }
    }

    drawRipples(c) {
      const t = this.t;
      c.lineWidth = 1; c.lineCap = "round";
      for (let bk = 0; bk < 4; bk++) {
        c.beginPath();
        for (const r of this.rip) {
          const a = 0.5 + 0.5 * Math.sin(t * r.sp + r.ph);
          if (Math.min(3, (a * 4) | 0) !== bk) continue;
          const x = r.x + Math.sin(t * 0.22 + r.ph) * 3;
          c.moveTo(x, r.y); c.quadraticCurveTo(x + r.l / 2, r.y - 1.6, x + r.l, r.y);
        }
        c.strokeStyle = `rgba(150,185,220,${(0.025 + bk * 0.022).toFixed(3)})`;
        c.stroke();
      }
      c.lineCap = "butt";
    }

    outline(c, n) {   // silhouette du conteneur (face avant + toit + bout)
      const g = this.g, x = n.x, y = n.y, w = n.w;
      c.beginPath(); c.moveTo(x, y + g.H); c.lineTo(x, y); c.lineTo(x + g.DX, y - g.DY); c.lineTo(x + w + g.DX, y - g.DY);
      c.lineTo(x + w + g.DX, y + g.H - g.DY); c.lineTo(x + w, y + g.H); c.closePath();
    }

    sprite(n) {
      const g = this.g, dpr = this.dpr, mode = n.up ? "up" : "down";
      const key = `${n.w}|${g.H}|${g.s}|${dpr}|${n.cat}|${mode}|${n.inv ? 1 : 0}|${n.label}`;
      let cv = this.sprites.get(key);
      if (cv) return cv;
      if (this.sprites.size > 500) this.sprites.clear();
      const w = n.w, H = g.H, DX = g.DX, DY = g.DY, s = g.s, p = paint(n.cat, mode), R = g.R;
      cv = document.createElement("canvas");
      cv.width = Math.ceil((w + DX + 2 * SP) * dpr); cv.height = Math.ceil((H + DY + 2 * SP) * dpr);
      const c = cv.getContext("2d");
      c.scale(dpr, dpr); c.translate(SP, SP + DY);
      // toit
      c.fillStyle = p.top; c.beginPath(); c.moveTo(0, 0); c.lineTo(DX, -DY); c.lineTo(w + DX, -DY); c.lineTo(w, 0); c.closePath(); c.fill();
      c.strokeStyle = "rgba(0,0,0,.09)"; c.lineWidth = 1; c.beginPath();
      for (let x = 6 * s; x < w - 2; x += 6 * s) { c.moveTo(x, 0); c.lineTo(x + DX, -DY); }
      c.stroke();
      // bout : les portes (deux vantaux)
      c.fillStyle = p.end; c.beginPath(); c.moveTo(w, 0); c.lineTo(w + DX, -DY); c.lineTo(w + DX, H - DY); c.lineTo(w, H); c.closePath(); c.fill();
      c.strokeStyle = "rgba(0,0,0,.3)"; c.beginPath(); c.moveTo(w + DX / 2, -DY / 2 + 2 * s); c.lineTo(w + DX / 2, H - DY / 2 - 2 * s); c.stroke();
      // face avant : tôle ondulée, lisses, montants, pièces de coin
      c.fillStyle = p.front; c.fillRect(0, 0, w, H);
      for (let x = 4 * s, i = 0; x < w - 3 * s; x += 3 * s, i++) { c.fillStyle = i % 2 ? p.ribL : p.ribD; c.fillRect(Math.round(x), 2.5 * s, 1, H - 5 * s); }
      c.fillStyle = p.rail; c.fillRect(0, 0, w, 2 * s);
      c.fillStyle = p.post; c.fillRect(0, H - 2 * s, w, 2 * s); c.fillRect(0, 0, 2 * s, H); c.fillRect(w - 2 * s, 0, 2 * s, H);
      c.fillStyle = p.cast;
      for (const [cx, cy] of [[0, 0], [w - 3 * s, 0], [0, H - 3 * s], [w - 3 * s, H - 3 * s]]) c.fillRect(cx, cy, 3 * s, 3 * s);
      // groupe frigorifique (le ventilateur et le voyant sont animés à part)
      c.fillStyle = "rgba(0,0,0,.32)"; rr(c, R.x, R.y, R.w, R.h, 1.5 * s); c.fill();
      c.strokeStyle = "rgba(255,255,255,.15)"; c.beginPath(); c.arc(R.cx, R.cy, R.r + 0.9 * s, 0, 6.283); c.stroke();
      // rouille et coulures (conteneurs à l'arrêt)
      if (mode === "down") {
        const r = rng(hash(n.key));
        c.fillStyle = "rgba(150,92,52,.42)";
        for (let i = 0; i < 6; i++) c.fillRect(R.x + R.w + 2 * s + r() * (w - R.w - 10 * s), 2 * s, 1.2 * s, (3 + r() * 8) * s);
        c.fillStyle = "rgba(160,98,55,.38)";
        for (let i = 0; i < 4; i++) { c.beginPath(); c.ellipse(3 * s + r() * (w - 6 * s), H - (2.5 + r() * 3) * s, (2 + r() * 3) * s, 1.2 * s, 0, 0, 6.283); c.fill(); }
      }
      // plaque nominative
      const px0 = R.x + R.w + 3 * s, avail = w - px0 - 3.5 * s;
      let fs = s < 0.9 ? 9.5 : 10, txt = n.label;
      c.font = `600 ${fs}px ${FONT}`;
      while (c.measureText(txt).width > avail - 7 * s && fs > 9) { fs -= 0.5; c.font = `600 ${fs}px ${FONT}`; }
      if (c.measureText(txt).width > avail - 7 * s) {
        while (txt.length > 2 && c.measureText(txt + "…").width > avail - 7 * s) txt = txt.slice(0, -1);
        txt += "…";
      }
      const pw = Math.min(avail, c.measureText(txt).width + 8 * s), ph = 13 * s, px = px0 + (avail - pw) / 2, py = (H - ph) / 2;
      c.fillStyle = mode === "up" ? "rgba(0,0,0,.42)" : "rgba(0,0,0,.3)"; rr(c, px, py, pw, ph, 2.5 * s); c.fill();
      c.fillStyle = mode === "up" ? "#f2f2f7" : "#a1a1a6"; c.textAlign = "center"; c.textBaseline = "middle";
      c.fillText(txt, px + pw / 2, py + ph / 2 + 0.5);
      // contour net ; pointillés pour l'inventaire
      c.strokeStyle = "rgba(0,0,0,.35)"; c.lineWidth = 1; c.strokeRect(0.5, 0.5, w - 1, H - 1);
      if (n.inv) {
        c.setLineDash([3 * s, 2.5 * s]); c.strokeStyle = "rgba(235,235,245,.75)";
        c.beginPath(); c.moveTo(0.5, H - 0.5); c.lineTo(0.5, 0.5); c.lineTo(DX + 0.5, -DY + 0.5); c.lineTo(w + DX - 0.5, -DY + 0.5);
        c.lineTo(w + DX - 0.5, H - DY - 0.5); c.lineTo(w - 0.5, H - 0.5); c.closePath(); c.stroke(); c.setLineDash([]);
      }
      this.sprites.set(key, cv);
      return cv;
    }

    drawNode(c, n, hl) {
      const a = n.alpha * n.fa * (n.up ? 1 : 0.62);
      n.solid = false;
      if (a < 0.01 || !n.w) return;
      const g = this.g, dpr = this.dpr, spr = this.sprite(n);
      const x = (n.dx = Math.round(n.x * dpr) / dpr), y = (n.dy = Math.round(n.y * dpr) / dpr);
      c.globalAlpha = a;
      c.drawImage(spr, x - SP, y - g.DY - SP, spr.width / dpr, spr.height / dpr);
      if (n.alpha >= 0.995 && n.fa >= 0.995) n.solid = true;   // au repos : ventilateur, voyant et LED tracés en lot par drawShelf
      else this.drawLive(c, n, a);
      c.globalAlpha = 1;
      if (hl && n.match && n.alpha > 0.3) { this.outline(c, n); c.strokeStyle = "rgba(255,255,255,.55)"; c.lineWidth = 1; c.stroke(); }
      if (!n.gone) this.drawList.push(n);
    }
    drawShelf(c, nodes, hl) {
      for (const n of nodes) this.drawNode(c, n, hl);
      const g = this.g, s = g.s, R = g.R;
      // ventilateurs des groupes frigo : vitesse ∝ CPU (un seul tracé)
      c.strokeStyle = "rgba(235,235,240,.62)"; c.lineWidth = 1.2 * s; c.beginPath();
      for (const n of nodes) {
        if (!n.solid || !n.up || n.inv) continue;
        const cx = n.dx + R.cx, cy = n.dy + R.cy;
        for (let b = 0; b < 3; b++) { const an = n.fan + b * 2.094; c.moveTo(cx, cy); c.lineTo(cx + Math.cos(an) * R.r, cy + Math.sin(an) * R.r); }
      }
      c.stroke();
      for (const n of nodes) if (n.solid && n.up && !n.inv) this.voyant(c, n, 1);
      c.globalAlpha = 1;
      // LED d'état sur les portes, groupées par couleur (inventaire : atténuées)
      for (const inv of [false, true]) {
        c.globalAlpha = inv ? 0.5 : 1;
        for (const lv of ["ok", "warn", "crit", "off", "blink"]) {
          let any = false;
          c.beginPath();
          for (const n of nodes) {
            if (!n.solid || n.lvl !== lv || (n.inv && n.up) !== inv) continue;
            const lx = n.dx + n.w + g.DX * 0.5, ly = n.dy - g.DY * 0.5 + 6 * s;
            c.moveTo(lx + 1.8 * s, ly); c.arc(lx, ly, 1.8 * s, 0, 6.283); any = true;
          }
          if (!any) continue;
          c.fillStyle = lv === "blink" ? (Math.sin(this.t * 7) > 0 ? LED.warn : LED.off) : LED[lv];
          c.fill();
        }
      }
      c.globalAlpha = 1;
    }
    voyant(c, n, a) {   // voyant du groupe frigo : pulse d'autant plus vite que la charge est forte ; ambre au-delà de 80 %
      const g = this.g, s = g.s, R = g.R, cpu = +n.d.cpu || 0, pu = 0.5 + 0.5 * Math.sin(n.vph), k = Math.min(1, cpu / 60);
      c.globalAlpha = a * (0.3 + 0.7 * (cpu < 0.5 ? 0.25 : 0.35 + 0.65 * pu * (0.4 + 0.6 * k)));
      c.fillStyle = cpu >= 80 ? LED.warn : "#e5e5ea";
      c.fillRect(n.dx + R.cx - 1.2 * s, n.dy + R.vy - 1.2 * s, 2.4 * s, 2.4 * s);
    }
    drawLive(c, n, a) {   // même chose à l'unité, pour un conteneur en cours de fondu ou atténué par le filtre
      const g = this.g, s = g.s, R = g.R;
      if (n.up && !n.inv) {
        const cx = n.dx + R.cx, cy = n.dy + R.cy;
        c.strokeStyle = "rgba(235,235,240,.62)"; c.lineWidth = 1.2 * s; c.beginPath();
        for (let b = 0; b < 3; b++) { const an = n.fan + b * 2.094; c.moveTo(cx, cy); c.lineTo(cx + Math.cos(an) * R.r, cy + Math.sin(an) * R.r); }
        c.stroke();
        this.voyant(c, n, a);
      }
      c.globalAlpha = a * (n.inv && n.up ? 0.5 : 1);
      c.fillStyle = n.lvl === "blink" ? (Math.sin(this.t * 7) > 0 ? LED.warn : LED.off) : LED[n.lvl] || LED.off;
      c.beginPath(); c.arc(n.dx + n.w + g.DX * 0.5, n.dy - g.DY * 0.5 + 6 * s, 1.8 * s, 0, 6.283); c.fill();
      c.globalAlpha = a;
    }

    drawTruck(c, tr) {
      const g = this.g, s = g.s, hor = Math.abs(tr.hx) >= Math.abs(tr.hy), dir = hor ? Math.sign(tr.hx) || 1 : Math.sign(tr.hy) || 1;
      const len = 21 * s, wid = 9 * s, cab = 6 * s;
      const w = hor ? len : wid, h = hor ? wid : len, x = tr.x - w / 2, y = tr.y - h / 2;
      const fade = Math.min(1, tr.d / (10 * s)) * (tr.n.fa > 0.5 ? 1 : 0.3);   // apparaît/disparaît en douceur au quai
      c.globalAlpha = fade;
      c.fillStyle = "rgba(0,0,0,.4)"; c.fillRect(x + 1 * s, y + 1.5 * s, w, h);                 // ombre plate
      c.fillStyle = "#0e0e10";                                                                // roues
      if (hor) for (const k of [0.18, 0.42, 0.82]) { const wx = dir > 0 ? x + w * k : x + w * (1 - k); c.fillRect(wx - 1.6 * s, y + h - 0.6 * s, 3.2 * s, 1.6 * s); }
      // plateau (remorque) puis cabine claire avec pare-brise
      let bx, by;
      if (hor) {
        const tx0 = dir > 0 ? x : x + cab + 1 * s;
        c.fillStyle = "#3a3a3e"; c.fillRect(tx0, y + 1 * s, w - cab - 1 * s, h - 2 * s);
        c.fillStyle = "#58585e"; c.fillRect(tx0, y + 1 * s, w - cab - 1 * s, 1 * s);
        const cx0 = dir > 0 ? x + w - cab : x;
        c.fillStyle = "#e5e5ea"; c.fillRect(cx0, y, cab, h);
        c.fillStyle = "#2c2c2e"; c.fillRect(dir > 0 ? cx0 + cab - 1.6 * s : cx0, y + 1.2 * s, 1.6 * s, h - 2.4 * s);
        bx = tx0 + (w - cab - 1 * s) / 2; by = tr.y;
      } else {
        const ty0 = dir > 0 ? y : y + cab + 1 * s;
        c.fillStyle = "#3a3a3e"; c.fillRect(x + 1 * s, ty0, w - 2 * s, h - cab - 1 * s);
        const cy0 = dir > 0 ? y + h - cab : y;
        c.fillStyle = "#e5e5ea"; c.fillRect(x, cy0, w, cab);
        c.fillStyle = "#2c2c2e"; c.fillRect(x + 1.2 * s, dir > 0 ? cy0 + cab - 1.6 * s : cy0, w - 2.4 * s, 1.6 * s);
        bx = tr.x; by = ty0 + (h - cab - 1 * s) / 2;
      }
      // colis : bleu = reçu (↓, vers le conteneur), orange = envoyé (↑, vers le quai)
      const box = (px, py, col, al = 1) => {
        c.globalAlpha = fade * al;
        c.fillStyle = col; c.fillRect(px - 3.2 * s, py - 2.8 * s, 6.4 * s, 5 * s);
        c.fillStyle = "rgba(255,255,255,.4)"; c.fillRect(px - 3.2 * s, py - 2.8 * s, 6.4 * s, 1.2 * s);
      };
      if (tr.ph === 0 && tr.pin) box(bx, by, PARCEL.rx);
      else if (tr.ph === 2 && tr.pout) box(bx, by, PARCEL.tx);
      else if (tr.ph === 1) {   // transbordement : le colis saute entre le camion et la porte du conteneur
        const n = tr.n, k = 1 - tr.wait / 0.9, ex = n.x + n.w * 0.55, ey = n.y + g.H * 0.75;
        const lerp = (u, a0, b0) => [a0[0] + (b0[0] - a0[0]) * u, a0[1] + (b0[1] - a0[1]) * u - Math.sin(u * Math.PI) * 8 * s];
        if (tr.pin && k < 0.5) { const [px, py] = lerp(k * 2, [bx, by], [ex, ey]); box(px, py, PARCEL.rx, 1 - Math.max(0, k * 2 - 0.7) / 0.3); }
        if (tr.pout && k >= 0.5) { const [px, py] = lerp((k - 0.5) * 2, [ex, ey], [bx, by]); box(px, py, PARCEL.tx, Math.min(1, ((k - 0.5) * 2) / 0.3)); }
      }
      c.globalAlpha = 1;
    }

    drawCrane(c, T, front) {
      const g = this.g, s = g.s, k = T.crane, legW = 3.2 * s, gh = 5 * s, bx = g.DX * 1.9, by = -g.DY * 1.9;
      const gl = k.gy, top = gl - k.lv * g.H - g.DY - 9 * s, xl = k.x - k.hw, xr = k.x + k.hw - legW;
      if (!front) {   // pieds et poutre arrière : derrière les conteneurs
        c.fillStyle = CRANE.dark;
        c.fillRect(xl + bx, top + by, legW, gl - top);
        c.fillRect(xr + bx, top + by, legW, gl - top);
        c.fillRect(xl + bx, top + by - gh, xr - xl + legW, gh);
        return;
      }
      // traverses d'extrémité (vues de dessus)
      c.fillStyle = CRANE.light;
      for (const ex of [xl, xr]) { c.beginPath(); c.moveTo(ex, top - gh); c.lineTo(ex + bx, top - gh + by); c.lineTo(ex + bx + legW, top - gh + by); c.lineTo(ex + legW, top - gh); c.closePath(); c.fill(); }
      // chariot sur les poutres, câbles et palonnier (spreader) au-dessus de la pile visée
      const tx = k.x + bx * 0.5 + k.tro, ty = top - gh + by * 0.5;
      const spx = k.x + g.DX * 0.5, spy = k.top - g.DY * 0.5 - 4 * s - k.hoist;
      c.strokeStyle = "rgba(210,210,215,.5)"; c.lineWidth = 1; c.beginPath();
      c.moveTo(tx - 3.5 * s, ty); c.lineTo(spx - k.sw * 0.26, spy - 2.2 * s);
      c.moveTo(tx + 3.5 * s, ty); c.lineTo(spx + k.sw * 0.26, spy - 2.2 * s);
      c.stroke();
      c.fillStyle = CRANE.cab; c.fillRect(tx - 7 * s, ty - 4 * s, 14 * s, 4 * s);
      c.fillStyle = CRANE.cabTop; c.beginPath(); c.moveTo(tx - 7 * s, ty - 4 * s); c.lineTo(tx - 4 * s, ty - 6.5 * s); c.lineTo(tx + 10 * s, ty - 6.5 * s); c.lineTo(tx + 7 * s, ty - 4 * s); c.closePath(); c.fill();
      c.fillStyle = CRANE.main; c.fillRect(spx - k.sw / 2, spy - 2.2 * s, k.sw, 2.2 * s);
      c.fillStyle = CRANE.dark; c.fillRect(spx - k.sw / 2, spy - 2.8 * s, 2.6 * s, 3.2 * s); c.fillRect(spx + k.sw / 2 - 2.6 * s, spy - 2.8 * s, 2.6 * s, 3.2 * s);
      // pieds avant, goussets, roues
      c.fillStyle = CRANE.main;
      c.fillRect(xl, top, legW, gl - top + 4 * s); c.fillRect(xr, top, legW, gl - top + 4 * s);
      c.beginPath(); c.moveTo(xl + legW, top); c.lineTo(xl + legW + 6 * s, top); c.lineTo(xl + legW, top + 6 * s); c.closePath();
      c.moveTo(xr, top); c.lineTo(xr - 6 * s, top); c.lineTo(xr, top + 6 * s); c.closePath(); c.fill();
      c.fillStyle = "#101012"; c.fillRect(xl - 1.5 * s, gl + 3 * s, legW + 3 * s, 2.6 * s); c.fillRect(xr - 1.5 * s, gl + 3 * s, legW + 3 * s, 2.6 * s);
      // poutre avant + arête éclairée, cabine du grutier
      c.fillStyle = CRANE.main; c.fillRect(xl, top - gh, xr - xl + legW, gh);
      c.fillStyle = CRANE.light; c.fillRect(xl, top - gh, xr - xl + legW, 1 * s);
      c.fillStyle = CRANE.cab; c.fillRect(xl + legW + 1 * s, top + 1 * s, 6.5 * s, 5.5 * s);
      c.fillStyle = "#1c1c1e"; c.fillRect(xl + legW + 2.3 * s, top + 2.3 * s, 3.9 * s, 2 * s);
    }

    drawShip(c, T) {
      const g = this.g, s = g.s, sh = T.ship, L = sh.L;
      if (L < 20) return;
      const f = sh.f, bob = this.reduced ? 0 : Math.sin(this.t * (0.8 + f * 0.6) + sh.ph) * (0.5 + f * 1.0) * s;
      const x0 = T.x + (T.w - L) / 2, wl = T.berth + g.BERTH * 0.76 + bob, dk = wl - 12 * s;
      const bow = Math.min(28 * s, L * 0.17), ddy = g.DY * 1.8;
      // amarres et bollards (suivent le roulis)
      c.strokeStyle = "rgba(200,200,205,.32)"; c.lineWidth = 1; c.beginPath();
      c.moveTo(x0 + 6 * s, dk - ddy * 0.4); c.lineTo(x0 - 10 * s, T.edge - 4 * s);
      c.moveTo(x0 + L - bow - 2 * s, dk - ddy * 0.4); c.lineTo(x0 + L + 10 * s, T.edge - 4 * s);
      c.stroke();
      c.fillStyle = "#636366"; c.beginPath();
      for (const bxp of [x0 - 10 * s, x0 + L + 10 * s]) { c.moveTo(bxp + 2.3 * s, T.edge - 4 * s); c.arc(bxp, T.edge - 4 * s, 2.3 * s, 0, 6.283); }
      c.fill();
      // navire : sprite mis en cache, redessiné seulement si sa longueur ou son chargement change
      const slots = Math.max(0, Math.floor((L - bow - 3 * s - (6 * s + g.DX * 1.8 * 0.2 + 20 * s + g.DX * 1.8 * 0.6 + 5 * s)) / (14 * s)));
      const fill = Math.round(slots * (0.18 + 0.82 * f) * 4) / 4, tiers = f > 0.55 ? 2 : 1, PL = 4 * s, PT = 66 * s;
      const key = `${Math.round(L)}|${fill}|${tiers}|${s}|${this.dpr}`;
      if (T.shipKey !== key) {
        const cv = T.shipCv || (T.shipCv = document.createElement("canvas")), dpr = this.dpr;
        cv.width = Math.ceil((L + g.DX * 1.8 + 2 * PL) * dpr); cv.height = Math.ceil((PT + 8 * s) * dpr);
        const sc = cv.getContext("2d");
        sc.setTransform(dpr, 0, 0, dpr, 0, 0); sc.clearRect(0, 0, cv.width, cv.height);
        this.renderShip(sc, T, PL, PT, L, fill, tiers);
        T.shipKey = key;
      }
      c.drawImage(T.shipCv, x0 - PL, wl - PT, T.shipCv.width / this.dpr, T.shipCv.height / this.dpr);
      // vague d'étrave, discrète, proportionnelle au trafic
      if (f > 0.05 && !this.reduced) {
        c.strokeStyle = `rgba(210,225,240,${(0.08 + 0.18 * f).toFixed(3)})`; c.lineWidth = 1; c.beginPath();
        for (let i = 0; i < 3; i++) { const ph = (this.t * 0.6 + i / 3) % 1, xx = x0 + L - bow * 0.45 + ph * 14 * s; c.moveTo(xx, wl + 1.5 * s + ph * 2 * s); c.lineTo(xx + 5 * s, wl + 1.5 * s + ph * 2 * s); }
        c.stroke();
      }
    }
    renderShip(c, T, x0, wl, L, fill, tiers) {   // coque, château, cheminée, conteneurs en pontée (repère local)
      const g = this.g, s = g.s, hh = 12 * s, dk = wl - hh;
      const bow = Math.min(28 * s, L * 0.17), ddx = g.DX * 1.8, ddy = g.DY * 1.8;
      c.fillStyle = "rgba(0,0,0,.25)"; c.fillRect(x0 + 4 * s, wl + 1, L - bow * 0.6, 3 * s);   // reflet sombre, plat
      // pont (vu de dessus) puis coque
      c.fillStyle = "#3d434a"; c.beginPath();
      c.moveTo(x0, dk); c.lineTo(x0 + L - bow, dk); c.lineTo(x0 + L, dk - ddy / 2); c.lineTo(x0 + L - bow + ddx, dk - ddy); c.lineTo(x0 + ddx, dk - ddy); c.closePath(); c.fill();
      c.beginPath();
      c.moveTo(x0, dk); c.lineTo(x0 + L - bow, dk); c.lineTo(x0 + L, dk - ddy / 2); c.lineTo(x0 + L - bow * 0.45, wl); c.lineTo(x0 + 3 * s, wl); c.lineTo(x0, wl - hh * 0.35); c.closePath();
      c.fillStyle = "#283039"; c.fill();
      c.save(); c.clip(); c.fillStyle = "#6b3a37"; c.fillRect(x0, wl - 2.8 * s, L, 3 * s); c.restore();   // ligne de flottaison
      c.fillStyle = "rgba(255,255,255,.09)"; c.fillRect(x0, dk, L - bow, 1);
      // nom du navire sur la coque
      c.font = `600 ${7 * s}px ${FONT}`; c.textAlign = "right"; c.textBaseline = "middle"; c.fillStyle = "rgba(235,235,245,.45)";
      if (L > 150 * s) c.fillText(TERM[T.host].ship, x0 + L - bow - 4 * s, dk + hh * 0.42);
      // château (passerelle) à la poupe, cheminée aux couleurs du terminal
      const qx = x0 + 6 * s + ddx * 0.2, qy = dk - ddy * 0.2, qw = 20 * s, qh = 16 * s, qd = ddx * 0.6;
      c.fillStyle = "#3a3a3c"; c.fillRect(qx + 5 * s + qd * 0.5, qy - qh - 8 * s - qd * 0.5, 6 * s, 8 * s);
      c.fillStyle = TERM[T.host].accent; c.globalAlpha = 0.7; c.fillRect(qx + 5 * s + qd * 0.5, qy - qh - 6 * s - qd * 0.5, 6 * s, 1.6 * s); c.globalAlpha = 1;
      c.fillStyle = "#aeaeb2"; c.beginPath(); c.moveTo(qx + qw, qy); c.lineTo(qx + qw + qd, qy - qd); c.lineTo(qx + qw + qd, qy - qh - qd); c.lineTo(qx + qw, qy - qh); c.closePath(); c.fill();
      c.fillStyle = "#e5e5ea"; c.beginPath(); c.moveTo(qx, qy - qh); c.lineTo(qx + qd, qy - qh - qd); c.lineTo(qx + qw + qd, qy - qh - qd); c.lineTo(qx + qw, qy - qh); c.closePath(); c.fill();
      c.fillStyle = "#c7c7cc"; c.fillRect(qx, qy - qh, qw, qh);
      c.fillStyle = "#2c2c2e";
      for (let wx = qx + 2.5 * s; wx < qx + qw - 3 * s; wx += 4 * s) c.fillRect(wx, qy - qh + 3 * s, 2.2 * s, 2.2 * s);
      // conteneurs en pontée : leur nombre suit le trafic du terminal
      const cw = 12 * s, gap = 2 * s, xs = qx + qw + qd + 5 * s, xe = x0 + L - bow - 3 * s;
      const slots = Math.max(0, Math.floor((xe - xs) / (cw + gap)));
      const cats = ["apps", "db", "media", "download", "infra", "ia", "dev", "autre"], r = rng(hash(T.host));
      const order = [];
      for (let i = 0; i < slots; i++) order.push(cats[(r() * cats.length) | 0], cats[(r() * cats.length) | 0]);
      for (let tier = 0; tier < tiers; tier++) {
        for (let i = 0; i < slots; i++) {
          const idx = i + tier * slots, al = clamp((tier ? fill * 0.6 : fill) - i, 0, 1);
          if (al <= 0.02) continue;
          const p = paint(order[idx], "up"), bxp = xs + i * (cw + gap) + ddx * 0.25, byp = dk - ddy * 0.25 - tier * 6.5 * s;
          c.globalAlpha = al;
          c.fillStyle = p.miniTop; c.beginPath(); c.moveTo(bxp, byp - 6.5 * s); c.lineTo(bxp + ddx * 0.4, byp - 6.5 * s - ddy * 0.4); c.lineTo(bxp + cw + ddx * 0.4, byp - 6.5 * s - ddy * 0.4); c.lineTo(bxp + cw, byp - 6.5 * s); c.closePath(); c.fill();
          c.fillStyle = p.mini; c.fillRect(bxp, byp - 6.5 * s, cw, 6.5 * s);
          c.fillStyle = "rgba(0,0,0,.25)"; c.fillRect(bxp + cw - 1, byp - 6.5 * s, 1, 6.5 * s);
        }
      }
      c.globalAlpha = 1;
    }

    fitHead(T) {   // en-tête du terminal, rendu dans un petit canvas mis en cache
      const g = this.g, s = g.s, st = T.st, dpr = this.dpr;
      const cv = T.hcv || (T.hcv = document.createElement("canvas"));
      cv.width = Math.ceil(T.w * dpr); cv.height = Math.ceil(g.HEAD * dpr);
      const c = cv.getContext("2d");
      c.setTransform(dpr, 0, 0, dpr, 0, 0);
      c.font = `600 ${13 * s}px ${FONT}`;
      const tw = c.measureText(T.title).width;
      c.font = `400 ${11.5 * s}px ${FONT}`;
      const net = `↓ ${fmtRate(st.rx)}   ↑ ${fmtRate(st.tx)}`;
      const full = st.inv ? `inventaire (sauvegarde NAS) · ${st.run}/${st.tot} en marche` : `${st.run}/${st.tot} en marche · CPU ${fmtPct(st.cpu)} · RAM ${fmtBytes(st.mem)} · ${net}`;
      const mid = st.inv ? `inventaire · ${st.run}/${st.tot}` : `${st.run}/${st.tot} · ${net}`;
      const room = T.w - 2 * g.PADX - tw - 14 * s, sw = c.measureText(T.sub).width + 12 * s;
      let hsub = "", hstat = "";
      for (const [sub, stat] of [[T.sub, full], ["", full], [T.sub, mid], ["", mid], ["", `${st.run}/${st.tot}`]]) {
        if ((sub ? sw : 0) + c.measureText(stat).width <= room) { hsub = sub; hstat = stat; break; }
      }
      const x = g.PADX, y = 19 * s;
      c.textBaseline = "middle"; c.textAlign = "left";
      c.font = `600 ${13 * s}px ${FONT}`; c.fillStyle = "#f5f5f7"; c.fillText(T.title, x, y);
      c.font = `400 ${11.5 * s}px ${FONT}`;
      if (hsub) { c.fillStyle = "#636366"; c.fillText(hsub, x + tw + 12 * s, y + 0.5); }
      if (hstat) { c.fillStyle = "#98989f"; c.textAlign = "right"; c.fillText(hstat, T.w - g.PADX, y + 0.5); }
    }
    drawHead(c, T) {
      if (T.hcv && T.hcv.width) c.drawImage(T.hcv, T.x, T.y, T.hcv.width / this.dpr, T.hcv.height / this.dpr);
    }

    /* ---------- interactions ---------- */
    pick(x, y) {
      const g = this.g;
      if (!g) return null;
      for (let i = this.drawList.length - 1; i >= 0; i--) {
        const n = this.drawList[i];
        if (n.alpha < 0.3 || x < n.x || x > n.x + n.w + g.DX || y < n.y - g.DY || y > n.y + g.H) continue;
        if (y < n.y && x < n.x + (n.y - y)) continue;                                  // coins découpés par la perspective
        if (x > n.x + n.w && y > n.y + g.H - (x - n.x - n.w)) continue;
        return n;
      }
      return null;
    }
    onMove(e) {
      this.mx = e.clientX; this.my = e.clientY;
      const r = this.cv.getBoundingClientRect(), n = this.pick(e.clientX - r.left, e.clientY - r.top);
      if (n !== this.hover) {
        this.hover = n; this.dirty = true;
        this.cv.style.cursor = n ? "pointer" : "";
        if (!n) untip();
      }
      if (n) tip(this.tipHtml(n), e.clientX, e.clientY);
    }
    onClick(e) {
      const r = this.cv.getBoundingClientRect(), n = this.pick(e.clientX - r.left, e.clientY - r.top);
      this.sel = n ? n.key : null; this.dirty = true;
      if (n) {
        if (e.pointerType === "touch" || (e.sourceCapabilities && e.sourceCapabilities.firesTouchEvents)) tip(this.tipHtml(n), e.clientX, e.clientY);
        if (typeof this.opts.onSelect === "function") this.opts.onSelect(n.d, n.host);
      }
    }
    tipHtml(n) {
      const d = n.d, p = paint(n.cat, "up"), [stTxt, stCls] = stateInfo(n), ports = parsePorts(d.ports);
      const row = (k, v) => `<div class="hb-tr"><span>${k}</span><span>${v}</span></div>`;
      const proj = d.project ? esc(d.project) : n.proj ? `${esc(n.proj)} <i>(déduit)</i>` : "autonome";
      return `<div class="hb-tip"><div class="hb-th"><i style="background:${p.swatch}"></i><b>${esc(d.name)}</b></div>` +
        (d.desc ? `<div class="hb-td">${esc(d.desc)}</div>` : "") +
        `<div class="hb-ts ${stCls}"><i></i>${esc(stTxt)}</div><div class="hb-tg">` +
        row("Terminal", esc(TERM[n.host].title.replace("Terminal ", ""))) + row("Projet", proj) + row("Catégorie", CAT_LABEL[n.cat]) +
        (n.inv ? "" : row("CPU", fmtPct(d.cpu)) + row("RAM", `${d.mem ? fmtBytes(d.mem) : "–"} <i>· ${n.size} pieds</i>`) +
          row("Réseau", `↓ ${fmtRate(d.rx)} · ↑ ${fmtRate(d.tx)}`)) +
        (ports.length ? row("Ports", esc(ports.join("  "))) : "") +
        row("Image", `<span class="hb-mono">${esc(d.image || "–")}</span>`) + (d.status ? row("Statut", esc(d.status)) : "") +
        `</div>${n.inv ? '<div class="hb-tn">Inventaire issu de la sauvegarde NAS : pas de métriques en direct.</div>' : ""}</div>`;
    }

    /* ---------- légende ---------- */
    buildLegend() {
      const fan = '<svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true"><rect x=".5" y=".5" width="11" height="11" rx="2" fill="#2c2c2e"/><path d="M6 6 6 2.4M6 6 9.1 7.8M6 6 2.9 7.8" stroke="#d1d1d6" stroke-width="1.2" stroke-linecap="round"/></svg>';
      this.lg.innerHTML = `<div class="hb-lg-row">${CATS.map((c) => `<span class="hb-chip" data-cat="${c}"><i style="background:${paint(c, "up").swatch}"></i>${CAT_LABEL[c]}<b data-n="${c}"></b></span>`).join("")}</div>
        <div class="hb-lg-row hb-lg-keys">
          <span><i class="hb-led" style="background:${LED.ok}"></i>en marche</span>
          <span><i class="hb-led" style="background:${LED.warn}"></i>démarrage / redémarrage</span>
          <span><i class="hb-led" style="background:${LED.crit}"></i>healthcheck en échec</span>
          <span><i class="hb-box"></i><i class="hb-box l"></i>20 / 40 pieds (RAM ≥ 500 Mo)</span>
          <span>${fan}ventilateur = CPU</span>
          <span><i class="hb-pk" style="background:${PARCEL.rx}"></i>reçu ↓<i class="hb-pk" style="background:${PARCEL.tx};margin-left:6px"></i>envoyé ↑</span>
          <span><i class="hb-wait"></i>zone d'attente = arrêtés</span>
          <span><i class="hb-inv"></i>inventaire, sans métriques</span>
        </div>`;
      this._lgOver = (e) => { const ch = e.target.closest(".hb-chip"), c = ch && !ch.classList.contains("off") ? ch.dataset.cat : null; if (c !== this.lcat) { this.lcat = c; this.refilter(); } };
      this._lgLeave = () => { if (this.lcat) { this.lcat = null; this.refilter(); } };
      this.lg.addEventListener("pointerover", this._lgOver);
      this.lg.addEventListener("pointerleave", this._lgLeave);
    }
    legendCounts() {
      const cnt = {};
      for (const n of this.nodes.values()) if (!n.gone) cnt[n.cat] = (cnt[n.cat] || 0) + 1;
      this.lg.querySelectorAll("[data-n]").forEach((b) => { const v = cnt[b.dataset.n] || 0; b.textContent = v || ""; b.parentNode.classList.toggle("off", !v); });
    }

    destroy() {
      cancelAnimationFrame(this.raf);
      this.ro.disconnect();
      if (this.io) this.io.disconnect();
      this.cv.removeEventListener("pointermove", this._move);
      this.cv.removeEventListener("pointerleave", this._leave);
      this.cv.removeEventListener("click", this._click);
      this.lg.removeEventListener("pointerover", this._lgOver);
      this.lg.removeEventListener("pointerleave", this._lgLeave);
      if (document.fonts) document.fonts.removeEventListener("loadingdone", this._fonts);
      if (this.hover) untip();
      this.root.remove();
      this.nodes.clear(); this.sprites.clear(); this.terms = [];
    }
  }

  window.Harbor = Harbor;
})();
