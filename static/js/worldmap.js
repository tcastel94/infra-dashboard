/* InfraDash — mini-carte du monde des flux sortants (canvas 2D, projection Miller recadrée lat -58..80).
   Terres en points (vendor/world-dots.json), domicile en bleu, un arc grand-cercle fin par lieu de destination
   (les destinations proches à l'écran sont agrégées), points qui voyagent le long des arcs, pastille ∝ connexions.
   Couleur par défaut = RISQUE (vert faible, orange moyen, rouge élevé) : c'est l'info actionnable ; la légende
   bascule en couleur par CATÉGORIE et sert de filtre (clic).
   Vue « Monde » ou « Europe » (zoom animé, cadré automatiquement sur les destinations européennes, grille fine 0,4°).
   API : const m = new WorldMap(el, {onSelect(dest, site), onFilter(f), colorBy:'risk'|'category', view:'world'|'europe',
                                     dotsUrl, landColor, tint})
         m.setData(egress) ; m.setFilter({category, risk, source}) ; m.setColorBy(mode) ; m.setView(mode) ;
         m.highlight(ip|null) ; m.destroy()
   Statiques : WorldMap.RISK, WorldMap.CAT, WorldMap.tipHtml(dest), WorldMap.blockLabel(method). */
(function () {
  "use strict";

  const SCRIPT_SRC = (document.currentScript && document.currentScript.src) || location.href;
  const DEG = Math.PI / 180;
  const miller = (lat) => 1.25 * Math.log(Math.tan(Math.PI / 4 + 0.4 * lat * DEG));
  const LAT_MAX = 80, LAT_MIN = -58;
  const Y_MAX = miller(LAT_MAX), Y_MIN = miller(LAT_MIN);
  const RATIO = (2 * Math.PI) / (Y_MAX - Y_MIN); // largeur / hauteur ≈ 2,11

  const RISK = { faible: ["#30D158", "Faible"], moyen: ["#FF9F0A", "Moyen"], eleve: ["#FF453A", "Élevé"] };
  const RISK_RANK = { faible: 0, moyen: 1, eleve: 2 };
  const CAT = {
    dns: ["#64D2FF", "DNS"], cloud: ["#4A9EFF", "Cloud"], cdn: ["#66D4CF", "CDN"], vpn: ["#BF5AF2", "VPN"],
    messagerie: ["#30D158", "Messagerie"], "iot-camera": ["#FF375F", "IoT / caméras"], push: ["#FFD60A", "Notifications push"],
    "maj-logiciels": ["#AC8E68", "Mises à jour"], stockage: ["#5E5CE6", "Stockage"], streaming: ["#FF9F0A", "Streaming"],
    "pub-tracking": ["#FF453A", "Pub / pistage"], inconnu: ["#8E8E93", "Inconnu"],
  };
  const BLOCK = {
    adguard: "AdGuard Home", dns: "DNS (AdGuard)", firewall: "Pare-feu", nftables: "nftables", iptables: "iptables",
    box: "Box / routeur", routeur: "Routeur", router: "Routeur", docker: "Docker", app: "Réglage de l'appli",
    ha: "Home Assistant", homeassistant: "Home Assistant", vpn: "VPN", unraid: "Unraid", hosts: "Fichier hosts", config: "Configuration",
  };
  const HOSTS = { nas: "NAS", homelab: "Homelab", clawhost: "clawhost", lan: "LAN", ha: "Home Assistant" };
  const KINDS = { container: "conteneur", vm: "VM", host: "hôte", lan: "appareil", device: "appareil", appareil: "appareil" };
  const HOME_C = "#4A9EFF";
  const FONT = '-apple-system, "Geist", system-ui, sans-serif';
  const nf = new Intl.NumberFormat("fr-FR");

  /* ---------- utilitaires ---------- */
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const num = (v) => (v === null || v === undefined || v === "" || !isFinite(+v) ? null : +v);
  const rgba = (hex, a) => { const n = parseInt(hex.slice(1), 16); return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`; };
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);
  const frac = (v) => v - Math.floor(v);
  const hash = (s) => { let h = 2166136261; for (const c of String(s)) h = Math.imul(h ^ c.charCodeAt(0), 16777619); return ((h >>> 0) % 1000) / 1000; };
  const degDist = (a, b) => Math.hypot((a.lat - b.lat), (a.lon - b.lon) * Math.cos(((a.lat + b.lat) / 2) * DEG));
  const list = (v) => (Array.isArray(v) ? v : v == null || v === "" ? [] : [v]);
  function relTime(ts) {
    if (!ts) return "";
    const ms = typeof ts === "number" ? (ts < 1e12 ? ts * 1000 : ts) : Date.parse(ts);
    if (!isFinite(ms)) return "";
    const s = Math.max(0, (Date.now() - ms) / 1000);
    if (s < 90) return "à l'instant";
    if (s < 3600) return `il y a ${Math.round(s / 60)} min`;
    if (s < 86400 * 2) return `il y a ${Math.round(s / 3600)} h`;
    return `il y a ${Math.round(s / 86400)} j`;
  }
  const blockLabel = (m) => BLOCK[String(m || "").toLowerCase()] || (m ? String(m) : "Blocage");
  const srcLabel = (s) => {
    const name = s.name || s.src_ip || s.host || "?";
    const where = HOSTS[s.host] || s.host || "";
    const kind = KINDS[s.kind] || s.kind || "";
    const tag = [where !== name ? where : "", kind].filter(Boolean).join(" · ");
    return `${esc(name)}${tag ? ` <span class="wm-mut">(${esc(tag)})</span>` : ""}`;
  };

  /* ---------- géométrie : terres en points (chargées une fois, partagées) ---------- */
  const DOTS = {};
  function decodeGrid(j) {
    const stepR = j.step * DEG, yMax = miller(j.latMax), pts = [];
    for (const row of j.rows) {
      const lat = row[0], ri = Math.round((yMax - miller(lat)) / stepR);
      for (let k = 1; k < row.length; k += 2) for (let c = row[k]; c < row[k] + row[k + 1]; c++) pts.push(j.lon0 + c * j.step, lat, c, ri);
    }
    return { lon0: j.lon0, lon1: j.lon0 + (j.cols || 0) * j.step, latMin: j.latMin, latMax: j.latMax, step: j.step, pts: Float32Array.from(pts) };
  }
  function loadDots(url) {
    if (!DOTS[url]) {
      DOTS[url] = fetch(url).then((r) => { if (!r.ok) throw new Error("world-dots " + r.status); return r.json(); })
        .then((j) => ({ lon0: j.lon0, world: decodeGrid(j), detail: j.detail ? decodeGrid(j.detail) : null }));
    }
    return DOTS[url];
  }

  // grand cercle (slerp) -> [[lon, lat], ...]
  function greatCircle(a, b, n) {
    const v = (p) => [Math.cos(p.lat * DEG) * Math.cos(p.lon * DEG), Math.cos(p.lat * DEG) * Math.sin(p.lon * DEG), Math.sin(p.lat * DEG)];
    const A = v(a), B = v(b);
    const d = Math.acos(clamp(A[0] * B[0] + A[1] * B[1] + A[2] * B[2], -1, 1));
    const out = [];
    for (let i = 0; i <= n; i++) {
      const t = i / n;
      if (d < 1e-6) { out.push([a.lon + (b.lon - a.lon) * t, a.lat + (b.lat - a.lat) * t]); continue; }
      const ka = Math.sin((1 - t) * d) / Math.sin(d), kb = Math.sin(t * d) / Math.sin(d);
      const x = ka * A[0] + kb * B[0], y = ka * A[1] + kb * B[1], z = ka * A[2] + kb * B[2];
      out.push([Math.atan2(y, x) / DEG, Math.atan2(z, Math.hypot(x, y)) / DEG]);
    }
    return out;
  }

  /* ---------- styles (injectés une fois, préfixe wm-) ---------- */
  function injectCss() {
    if (document.getElementById("wm-style")) return;
    const st = document.createElement("style");
    st.id = "wm-style";
    st.textContent = `
.wm{position:relative;color:#fff;font:12px/1.4 ${FONT};-webkit-font-smoothing:antialiased}
.wm-stage{position:relative;width:100%}
.wm-stage canvas{position:absolute;inset:0;width:100%;height:100%;display:block;touch-action:manipulation;-webkit-tap-highlight-color:transparent}
.wm-foot{display:flex;align-items:center;flex-wrap:wrap;gap:8px 14px;margin-top:10px}
.wm-legend{display:flex;align-items:center;flex-wrap:wrap;gap:6px 8px}
.wm-sum{margin-left:auto;color:#98989f;font-size:11px;font-variant-numeric:tabular-nums}
.wm-sum b{color:#fff;font-weight:600}
.wm-narrow .wm-sum{margin-left:0;width:100%}
.wm-seg{display:inline-flex;background:#1c1c1e;border:1px solid #313134;border-radius:8px;padding:2px}
.wm button{font:inherit;border:0;background:none;color:inherit;margin:0;cursor:pointer}
.wm button:focus-visible{outline:1px solid #4A9EFF;outline-offset:1px}
.wm-seg button{padding:2px 9px;border-radius:6px;color:#98989f;font-size:11px;transition:background .2s,color .2s}
.wm-seg button.on{background:#2c2c2e;color:#fff}
.wm-items{display:flex;flex-wrap:wrap;gap:2px 2px}
.wm-it{display:inline-flex;align-items:center;gap:6px;color:#98989f;font-size:11px;padding:2px 6px;border-radius:6px;transition:background .2s,color .2s,opacity .2s}
.wm-it i{width:7px;height:7px;border-radius:50%;background:var(--c);flex:none}
.wm-it.home i{box-shadow:0 0 0 2px #000,0 0 0 3px rgba(74,158,255,.5)}
.wm-it:hover{color:#fff}.wm-it.on{color:#fff;background:#2c2c2e}.wm-items.f .wm-it:not(.on):not(.home){opacity:.45}
.wm-empty[hidden]{display:none}
.wm-empty{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#98989f;font-size:13px;pointer-events:none}
.wm-tip{position:fixed;z-index:1000;pointer-events:none;background:rgba(28,28,30,.97);border:1px solid #313134;border-radius:12px;
  padding:10px 12px;color:#fff;font:12px/1.4 ${FONT};box-shadow:0 14px 34px -10px rgba(0,0,0,.85);opacity:0;transition:opacity .12s;max-width:340px}
.wm-tip.on{opacity:1}
.wm-tt{min-width:230px;max-width:320px;font:12px/1.4 ${FONT}}
.wm-tt-h{display:flex;align-items:center;gap:7px;font-weight:600;color:#fff;font-size:13px}
.wm-tt-h i{width:8px;height:8px;border-radius:50%;flex:none}
.wm-tt-s{display:flex;flex-wrap:wrap;gap:4px;margin:6px 0 7px}
.wm-tt-r{display:flex;justify-content:space-between;align-items:baseline;gap:14px;padding:1.5px 0}
.wm-tt-r>span:first-child{color:#98989f;white-space:nowrap}
.wm-tt-r>span:last-child{text-align:right;color:#fff;min-width:0;overflow-wrap:anywhere}
.wm-mono{font-family:ui-monospace,"Geist Mono",monospace;font-size:11px}
.wm-mut{color:#98989f}
.wm-pill{display:inline-block;padding:1px 7px;border-radius:6px;font-size:10.5px;font-weight:600;line-height:1.5}
.wm-tt-why{color:#c7c7cc;margin-top:7px;padding-top:7px;border-top:1px solid #313134}
.wm-tt-b{margin-top:7px;padding:7px 9px;background:#2c2c2e;border-radius:8px;color:#c7c7cc}
.wm-tt-b .wm-mono{display:block;margin-top:4px;color:#fff;overflow-wrap:anywhere}
.wm-tt-k{color:#98989f;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:2px}
.wm-tt-more{margin-top:7px;padding-top:7px;border-top:1px solid #313134}
.wm-tt-more div{display:flex;align-items:center;gap:7px;padding:1px 0}
.wm-tt-more i{width:6px;height:6px;border-radius:50%;flex:none}
.wm-tt-more span:last-child{margin-left:auto;color:#98989f;font-variant-numeric:tabular-nums}`;
    document.head.appendChild(st);
  }

  /* ---------- info-bulle ---------- */
  function tipHtml(w, more, local) {
    const d = w.d || w;
    const risk = RISK[w.risk || d.risk] || RISK.faible, cat = CAT[w.cat || d.category] || CAT.inconnu;
    const pill = (c, t) => `<span class="wm-pill" style="color:${c};background:${rgba(c, 0.15)}">${esc(t)}</span>`;
    const row = (k, v) => (v ? `<div class="wm-tt-r"><span>${k}</span><span>${v}</span></div>` : "");
    const place = [d.region, d.country_name || d.country].filter((x, i, a) => x && a.indexOf(x) === i).map(esc).join(", ");
    const srcs = list(d.sources);
    const ports = [...list(d.ports), ...(list(d.ports).length ? [] : list(d.protos))].join(", ");
    const b = list(d.block)[0];
    const seen = [d.first_seen ? `1re fois ${relTime(d.first_seen)}` : "", d.last_seen ? `dernière ${relTime(d.last_seen)}` : ""].filter(Boolean).join(" · ");
    let h = `<div class="wm-tt"><div class="wm-tt-h"><i style="background:${(w.color || risk[0])}"></i>${esc(d.service || d.ptr || d.ip || "Destination")}</div>`;
    h += `<div class="wm-tt-s">${pill(risk[0], "Risque " + risk[1].toLowerCase())}${pill(cat[0], cat[1])}`;
    h += d.eu === true ? pill("#4A9EFF", "UE") : d.eu === false ? pill("#98989f", "Hors UE") : "";
    h += d.is_new ? pill("#BF5AF2", "Nouveau") : "";
    h += `</div>`;
    h += row("Organisation", esc([d.org, d.asn].filter(Boolean).join(" · ")));
    h += row("Lieu", place);
    h += row("IP", d.ip ? `<span class="wm-mono">${esc(d.ip)}</span>` : "");
    h += d.ptr && d.ptr !== d.service ? row("PTR", `<span class="wm-mono">${esc(d.ptr.length > 44 ? d.ptr.slice(0, 42) + "…" : d.ptr)}</span>`) : "";
    h += row("Ports", ports ? `<span class="wm-mono">${esc(ports)}</span>` : "");
    h += row("Sources", srcs.slice(0, 4).map(srcLabel).join("<br>") + (srcs.length > 4 ? `<br><span class="wm-mut">+ ${srcs.length - 4} autre(s)</span>` : ""));
    h += row("Connexions", d.conns != null ? nf.format(d.conns) : "");
    h += row("Vu", esc(seen));
    if (d.why) h += `<div class="wm-tt-why">${esc(d.why)}</div>`;
    if (b) h += `<div class="wm-tt-b"><div class="wm-tt-k">Bloquer · ${esc(blockLabel(b.method))}</div>${esc(b.how || "")}${b.impact ? `<div class="wm-tt-why">⚠ ${esc(b.impact)}</div>` : ""}${b.rule ? `<span class="wm-mono">${esc(b.rule)}</span>` : ""}</div>`;
    if (more && more.length) {
      h += `<div class="wm-tt-more"><div class="wm-tt-k">${local ? "Aussi près du domicile" : "Aussi à cet endroit"}</div>` + more.slice(0, 6).map((m) =>
        `<div><i style="background:${m.color}"></i><span>${esc(m.d.service || m.d.ip)}</span><span>${nf.format(m.conns)}</span></div>`).join("") +
        (more.length > 6 ? `<div class="wm-mut">+ ${more.length - 6} autre(s)</div>` : "") + `</div>`;
    }
    return h + `</div>`;
  }

  /* ---------- composant ---------- */
  const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const EU_BOX = { lon0: -30, lon1: 60, latMin: 25, latMax: 72 };   // zone de cadrage de la vue Europe

  class WorldMap {
    constructor(el, opts = {}) {
      injectCss();
      this.el = el;
      this.opts = opts;
      this.colorBy = opts.colorBy === "category" ? "category" : "risk";
      this.mode = opts.view === "europe" ? "europe" : "world";
      this.filter = {};
      this.sites = new Map();      // clé -> état animé d'un lieu
      this.ipSite = new Map();     // ip -> clé de lieu (stabilité des clés entre mises à jour)
      this.data = null;
      this.clock = 0;
      this.hoverKey = null; this.hlKey = null;
      this.reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
      this.lon0 = -169;
      this.onscreen = true;
      this.view = null;            // {k, cx, cy} : zoom et centre (coordonnées « base » = carte entière à l'échelle 1)

      el.classList.add("wm");
      el.innerHTML = `<div class="wm-stage"><canvas aria-label="Carte du monde des flux sortants" role="img"></canvas><div class="wm-empty" hidden></div></div>
        <div class="wm-foot"><div class="wm-legend"><div class="wm-seg" role="group" aria-label="Cadrage"><button data-view="world">Monde</button><button data-view="europe">Europe</button></div><div class="wm-seg" role="group" aria-label="Couleur des arcs"><button data-mode="risk">Risque</button><button data-mode="category">Catégorie</button></div><div class="wm-items"></div></div>
        <div class="wm-sum"></div></div>`;
      this.stage = el.querySelector(".wm-stage");
      this.stage.style.aspectRatio = String(RATIO);
      this.canvas = el.querySelector("canvas");
      this.ctx = this.canvas.getContext("2d");
      this.legendEl = el.querySelector(".wm-legend");
      this.itemsEl = el.querySelector(".wm-items");
      this.sumEl = el.querySelector(".wm-sum");
      this.emptyEl = el.querySelector(".wm-empty");

      this._loop = this._loop.bind(this);
      this._onMove = this._onMove.bind(this);
      this._onLeave = this._onLeave.bind(this);
      this._onClick = this._onClick.bind(this);
      this._onLegend = this._onLegend.bind(this);
      this._onVis = () => this._kick();
      this._onAway = (e) => { if (this.tipMode && e.target !== this.canvas) { this._hideTip(); this.hoverKey = null; this._kick(); } };
      document.addEventListener("pointerdown", this._onAway, true);
      addEventListener("scroll", this._onAway, { capture: true, passive: true });
      this.canvas.addEventListener("pointermove", this._onMove);
      this.canvas.addEventListener("pointerleave", this._onLeave);
      this.canvas.addEventListener("click", this._onClick);
      this.legendEl.addEventListener("click", this._onLegend);
      document.addEventListener("visibilitychange", this._onVis);
      this._mq = matchMedia("(prefers-reduced-motion: reduce)");
      this._onMq = () => { this.reduced = this._mq.matches; this._kick(); };
      this._mq.addEventListener && this._mq.addEventListener("change", this._onMq);

      this._ro = new ResizeObserver(() => { this._layout(); this._kick(); });
      this._ro.observe(this.stage);
      if ("IntersectionObserver" in window) {
        this._io = new IntersectionObserver((ents) => { this.onscreen = ents[ents.length - 1].isIntersecting; this._kick(); });
        this._io.observe(this.stage);
      }
      const url = opts.dotsUrl || new URL("../vendor/world-dots.json", SCRIPT_SRC).href;
      loadDots(url).then((g) => { if (this.dead) return; this.geo = g; this.lon0 = g.lon0; this.sizeKey = null; this._layout(); this._kick(); })
        .catch((e) => console.warn("WorldMap : géométrie indisponible", e));
      this._legend();
      this._layout();
      this._kick();
    }

    /* ----- API publique ----- */
    setData(egress) {
      const eg = egress || {};
      const home = Object.assign({ lat: 48.86, lon: 2.35, label: "Domicile" }, eg.home || {});
      home.lat = num(home.lat) ?? 48.86; home.lon = num(home.lon) ?? 2.35;
      const cc = new Map(list(eg.countries).map((c) => [c.code, c]));
      const dests = list(eg.destinations).map((d) => {
        let lat = num(d.lat), lon = num(d.lon);
        const c = cc.get(d.country);
        if ((lat == null || lon == null) && c) { lat = num(c.lat); lon = num(c.lon); }
        return { d, ip: d.ip, lat, lon, conns: Math.max(1, +d.conns || 1), cat: CAT[d.category] ? d.category : "inconnu",
          risk: RISK[d.risk] ? d.risk : "faible", loc: lat != null && lon != null };
      });
      this.data = { home, dests, raw: eg };
      this._cluster();
      if (this.mode === "europe") this._retarget();   // le cadrage Europe suit les destinations
      this._legend();
      this._summary();
      this._kick();
      return this;
    }
    setFilter(f) {
      const n = (v) => (v == null || v === "" || v === "all" || v === "*" ? null : String(v));
      this.filter = { category: n(f && f.category), risk: n(f && f.risk), source: n(f && f.source) };
      this._legend();
      this._kick();
      return this;
    }
    setColorBy(mode) {
      this.colorBy = mode === "category" ? "category" : "risk";
      this._recolor(); this._legend(); this._kick();
      return this;
    }
    setView(mode) {
      this.mode = mode === "europe" ? "europe" : "world";
      this._retarget(true);
      this._legend(); this._kick();
      return this;
    }
    highlight(ip) {
      this.hlKey = ip ? this.ipSite.get(ip) || null : null;
      this._kick();
      return this;
    }
    destroy() {
      this.dead = true;
      cancelAnimationFrame(this.raf); clearTimeout(this.sleep);
      this._ro.disconnect(); this._io && this._io.disconnect();
      document.removeEventListener("visibilitychange", this._onVis);
      document.removeEventListener("pointerdown", this._onAway, true);
      removeEventListener("scroll", this._onAway, { capture: true });
      this._mq.removeEventListener && this._mq.removeEventListener("change", this._onMq);
      this._hideTip();
      this.el.innerHTML = ""; this.el.classList.remove("wm", "wm-narrow");
    }

    /* ----- projection et cadrage ----- */
    proj(lon, lat) {  // coordonnées « base » (carte entière, échelle 1)
      let l = lon;
      while (l < this.lon0) l += 360;
      while (l >= this.lon0 + 360) l -= 360;
      return [((l - this.lon0) / 360) * this.W, ((Y_MAX - miller(clamp(lat, LAT_MIN, LAT_MAX))) / (Y_MAX - Y_MIN)) * this.H];
    }
    scr(bx, by, v = this.view) { return [(bx - v.cx) * v.k + this.W / 2, (by - v.cy) * v.k + this.H / 2]; }
    _viewFor(mode) {
      const W = this.W, H = this.H;
      if (mode !== "europe" || !W) return { k: 1, cx: W / 2, cy: H / 2 };
      const home = this.data ? this.data.home : { lat: 48.86, lon: 2.35 };
      let lo = home.lon, hi = home.lon, la0 = home.lat, la1 = home.lat;
      for (const s of this.sites.values()) {
        if (!s.target || s.local || s.lon < EU_BOX.lon0 || s.lon > EU_BOX.lon1 || s.lat < EU_BOX.latMin || s.lat > EU_BOX.latMax) continue;
        lo = Math.min(lo, s.lon); hi = Math.max(hi, s.lon); la0 = Math.min(la0, s.lat); la1 = Math.max(la1, s.lat);
      }
      lo -= 5; hi += 5; la0 -= 3; la1 += 3;
      if (hi - lo < 28) { const m = (lo + hi) / 2; lo = m - 14; hi = m + 14; }
      if (la1 - la0 < 14) { const m = (la0 + la1) / 2; la0 = m - 7; la1 = m + 7; }
      const [x0, y1] = this.proj(lo, la0), [x1, y0] = this.proj(hi, la1);
      const g = (this.geo && this.geo.detail) || EU_BOX;
      const k = clamp(Math.min(W / (x1 - x0), H / (y1 - y0)), 4.2, 7.5);
      const [bx0, by0] = this.proj(g.lon0 + 0.5, g.latMax - 0.5), [bx1, by1] = this.proj(g.lon1 - 0.5, g.latMin + 0.5);
      const hw = W / 2 / k, hh = H / 2 / k;
      return { k, cx: clamp((x0 + x1) / 2, bx0 + hw, Math.max(bx0 + hw, bx1 - hw)), cy: clamp((y0 + y1) / 2, by0 + hh, Math.max(by0 + hh, by1 - hh)) };
    }
    // nouvelle cible de cadrage (transition animée sauf mouvement réduit)
    _retarget(animate) {
      if (!this.W) return;
      const to = this._viewFor(this.mode);
      const cur = this.vTo || this.view;
      if (cur && Math.abs(cur.k - to.k) < 0.02 && Math.hypot(cur.cx - to.cx, cur.cy - to.cy) < 0.5) return;
      if (this.mode === "europe") this.layerE = this._renderLayer(to, (this.geo && this.geo.detail) || (this.geo && this.geo.world));
      if (this.reduced || !this.view || animate === false) { this.view = to; this.vFrom = this.vTo = null; }
      else { this.vFrom = Object.assign({}, this.view); this.vTo = to; this.vT = 0; }
      this._cluster();
    }

    /* ----- mise en page ----- */
    _layout() {
      const W = this.stage.clientWidth, H = this.stage.clientHeight || W / RATIO;
      if (W < 20 || H < 10) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
      const sizeKey = `${W}x${H}@${dpr}`;
      this.el.classList.toggle("wm-narrow", W < 620);
      if (sizeKey === this.sizeKey) return;
      this.sizeKey = sizeKey; this.W = W; this.H = H; this.dpr = dpr;
      this.canvas.width = Math.round(W * dpr); this.canvas.height = Math.round(H * dpr);
      this.sc = clamp(W / 1100, 0.68, 1.25);
      this.vFrom = this.vTo = null;
      this.view = { k: 1, cx: W / 2, cy: H / 2 };
      this.layerW = this.geo ? this._renderLayer(this.view, this.geo.world) : null;
      this.layerE = null;
      this._cluster();
      if (this.mode === "europe") this._retarget(false);
    }
    // calque des terres pour un cadrage donné (bitmap à la résolution écran) + points gardés (pour la teinte)
    _renderLayer(v, grid) {
      if (!grid) return null;
      const W = this.W, H = this.H, dpr = this.dpr;
      const sp = (grid.step / 360) * W * v.k;
      const dec = sp < 1.9 ? 3 : sp < 3.6 ? 2 : 1;            // décimation sur petit écran : vrai « dot matrix »
      const r = clamp(sp * dec * 0.21, 0.6, 1.4);
      const cv = document.createElement("canvas");
      cv.width = this.canvas.width; cv.height = this.canvas.height;
      const c = cv.getContext("2d");
      c.setTransform(dpr, 0, 0, dpr, 0, 0);
      c.fillStyle = this.opts.landColor || "#3a3a3c";
      c.beginPath();
      const keep = [], P = grid.pts;
      for (let i = 0; i < P.length; i += 4) {
        if (dec > 1 && (P[i + 2] % dec || P[i + 3] % dec)) continue;
        const [bx, by] = this.proj(P[i], P[i + 1]);
        const [x, y] = this.scr(bx, by, v);
        if (x < -3 || x > W + 3 || y < -3 || y > H + 3) continue;
        c.moveTo(x + r, y); c.arc(x, y, r, 0, Math.PI * 2);
        keep.push(bx, by);
      }
      c.fill();
      return { cv, v, r, sp: sp * dec, pts: Float32Array.from(keep) };
    }

    /* ----- agrégation des destinations en lieux ----- */
    _cluster() {
      if (!this.data || !this.W) return;
      const { home, dests } = this.data;
      const k = (this.vTo || this.view || { k: 1 }).k;
      const thr = Math.max(9, 13 * this.sc) / k;             // seuil d'agrégation : constant à l'écran
      const groups = [];
      let local = null;
      const sorted = dests.filter((w) => w.loc).sort((a, b) => b.conns - a.conns || String(a.ip).localeCompare(String(b.ip)));
      for (const w of sorted) {
        if (degDist(w, home) < 0.9) { (local = local || { local: true, members: [] }).members.push(w); continue; }
        const [x, y] = this.proj(w.lon, w.lat);
        let g = groups.find((g) => Math.hypot(g.x - x, g.y - y) < thr);
        if (!g) groups.push((g = { x, y, lat: w.lat, lon: w.lon, members: [] }));
        g.members.push(w);
      }
      if (local) groups.push(local);
      groups.forEach((g, i) => { g.rank = i; });   // groupes déjà triés par connexions décroissantes (membre principal)
      // clés stables : un groupe hérite de la clé majoritaire (pondérée par connexions) de ses membres
      const used = new Set(), next = new Map(), ipSite = new Map();
      for (const g of groups) {
        let key = g.local ? "local" : null;
        if (!key) {
          const votes = new Map();
          for (const w of g.members) { const kk = this.ipSite.get(w.ip); if (kk && kk !== "local") votes.set(kk, (votes.get(kk) || 0) + w.conns); }
          const best = [...votes].filter(([kk]) => !used.has(kk)).sort((a, b) => b[1] - a[1])[0];
          key = best ? best[0] : "s:" + g.members[0].ip;
          if (used.has(key)) key += ":" + groups.indexOf(g);
        }
        used.add(key);
        let s = this.sites.get(key);
        if (!s) s = { key, alpha: 0, reveal: 0, r: 0, dim: 1, ph: 0, seed: hash(key) };
        s.target = 1;
        s.local = !!g.local;
        s.rank = g.local ? 0 : g.rank;
        s.members = g.members.slice().sort((a, b) => RISK_RANK[b.risk] - RISK_RANK[a.risk] || b.conns - a.conns);
        s.lat = g.lat; s.lon = g.lon;
        s.conns = g.members.reduce((t, w) => t + w.conns, 0);
        s.risk = s.members[0].risk;
        s.isNew = g.members.some((w) => w.d.is_new);
        const top = g.members[0].d;
        s.label = s.local ? home.label || "Domicile" : top.region || top.country_name || top.country || "";
        for (const w of g.members) ipSite.set(w.ip, key);
        next.set(key, s);
      }
      for (const [kk, s] of this.sites) if (!next.has(kk)) { s.target = 0; next.set(kk, s); }  // fondu de sortie
      this.sites = next; this.ipSite = ipSite;
      if (this.hlKey && !next.has(this.hlKey)) this.hlKey = null;
      this._recolor();
      this._paths();
    }
    _recolor() {
      for (const s of this.sites.values()) {
        for (const w of s.members) w.color = this.colorBy === "category" ? CAT[w.cat][0] : RISK[w.risk][0];
        if (this.colorBy === "category") {  // catégorie dominante (en connexions)
          const by = new Map();
          for (const w of s.members) by.set(w.cat, (by.get(w.cat) || 0) + w.conns);
          s.color = CAT[[...by].sort((a, b) => b[1] - a[1])[0][0]][0];
        } else s.color = RISK[s.risk][0];
      }
    }
    // arcs en coordonnées base : grand cercle projeté + léger galbe (lisibilité des arcs courts)
    _paths() {
      if (!this.data || !this.W) return;
      const home = this.data.home;
      const [hx, hy] = this.proj(home.lon, home.lat);
      this.hx = hx; this.hy = hy;
      for (const s of this.sites.values()) {
        s.tints = new Map();
        s.conR = Math.min(2 + 1.3 * Math.log10(s.conns + 1), 7);   // rayon écran (avant échelle)
        if (s.local) { s.x = hx; s.y = hy; continue; }
        let gc = greatCircle(home, s, 48);
        for (let i = 1; i < gc.length; i++) { while (gc[i][0] - gc[i - 1][0] > 180) gc[i][0] -= 360; while (gc[i][0] - gc[i - 1][0] < -180) gc[i][0] += 360; }
        const start = (hx / this.W) * 360 + this.lon0, shift = start - gc[0][0];
        if (gc.some((p) => p[0] + shift < this.lon0 || p[0] + shift >= this.lon0 + 360)) {   // franchit la couture du Pacifique
          const elon = (this.proj(s.lon, s.lat)[0] / this.W) * 360 + this.lon0;
          gc = gc.map((p, i, a) => [start + (elon - start) * (i / (a.length - 1)), p[1]]);
        } else gc = gc.map((p) => [p[0] + shift, p[1]]);
        const n = gc.length, xs = new Float32Array(n), ys = new Float32Array(n), cum = new Float32Array(n);
        for (let i = 0; i < n; i++) {
          xs[i] = ((gc[i][0] - this.lon0) / 360) * this.W;
          ys[i] = ((Y_MAX - miller(clamp(gc[i][1], LAT_MIN, LAT_MAX))) / (Y_MAX - Y_MIN)) * this.H;
        }
        const dx = xs[n - 1] - xs[0], dy = ys[n - 1] - ys[0], L = Math.hypot(dx, dy) || 1;
        let nx = -dy / L, ny = dx / L;
        if (ny > 0 || (Math.abs(ny) < 0.2 && nx > 0)) { nx = -nx; ny = -ny; }
        const bow = Math.min(L * 0.2, 42 * this.sc);
        for (let i = 1; i < n - 1; i++) { const b = Math.sin((Math.PI * i) / (n - 1)) * bow; xs[i] += nx * b; ys[i] += ny * b; }
        for (let i = 1; i < n; i++) cum[i] = cum[i - 1] + Math.hypot(xs[i] - xs[i - 1], ys[i] - ys[i - 1]);
        Object.assign(s, { xs, ys, cum, len: cum[n - 1], x: xs[n - 1], y: ys[n - 1] });
      }
    }
    // points de terre voisins d'une destination (teinte discrète : la région « s'allume »)
    _tint(s, L) {
      let t = s.tints.get(L);
      if (t) return t;
      const R = (L.sp * 2.6) / L.v.k, out = [], P = L.pts;
      for (let i = 0; i < P.length; i += 2) {
        const d = Math.hypot(P[i] - s.x, P[i + 1] - s.y);
        if (d < R) out.push(P[i], P[i + 1], 1 - d / R);
      }
      t = Float32Array.from(out);
      s.tints.set(L, t);
      return t;
    }
    _at(s, dist) {  // position (base) à une distance donnée le long d'un arc
      const { xs, ys, cum } = s, n = cum.length;
      if (dist <= 0) return [xs[0], ys[0]];
      if (dist >= cum[n - 1]) return [xs[n - 1], ys[n - 1]];
      let lo = 0, hi = n - 1;
      while (hi - lo > 1) { const m = (lo + hi) >> 1; if (cum[m] < dist) lo = m; else hi = m; }
      const t = (dist - cum[lo]) / (cum[hi] - cum[lo] || 1);
      return [xs[lo] + (xs[hi] - xs[lo]) * t, ys[lo] + (ys[hi] - ys[lo]) * t];
    }
    _match(w) {
      const f = this.filter;
      if (f.risk && w.risk !== f.risk) return false;
      if (f.category && w.cat !== f.category) return false;
      if (f.source) {
        const q = f.source.toLowerCase();
        if (!list(w.d.sources).some((s) => [s.host, s.name, s.src_ip].some((v) => v && String(v).toLowerCase() === q))) return false;
      }
      return true;
    }

    /* ----- boucle d'animation (pause si invisible) ----- */
    _visible() { return this.el.offsetParent !== null && !document.hidden && this.onscreen; }
    _kick() {
      if (this.dead || this.raf) return;
      clearTimeout(this.sleep); this.sleep = 0;
      this.raf = requestAnimationFrame(this._loop);
    }
    _loop(ts) {
      this.raf = 0;
      if (this.dead) return;
      if (!this._visible()) { this.last = 0; this.sleep = setTimeout(() => this._kick(), 600); return; }
      const dt = this.last ? clamp((ts - this.last) / 1000, 0, 0.1) : 0.016;
      this.last = ts;
      const busy = this._frame(dt);
      if (!this.reduced || busy) this.raf = requestAnimationFrame(this._loop);
      else this.last = 0;
    }
    _drawLayer(L, alpha, c = this.ctx) {
      if (!L || alpha < 0.01) return;
      const v = this.view, s = v.k / L.v.k, W = this.W, H = this.H, d = this.dpr;
      const ox = W / 2 - (s * W) / 2 + (L.v.cx - v.cx) * v.k, oy = H / 2 - (s * H) / 2 + (L.v.cy - v.cy) * v.k;
      c.setTransform(d * s, 0, 0, d * s, d * ox, d * oy);
      c.globalAlpha = alpha;
      c.drawImage(L.cv, 0, 0, W, H);
    }
    _drawDots(L, c) {
      if (!L) return;
      const v = this.view, d = this.dpr, k = v.k, W = this.W, H = this.H, P = L.pts;
      const r = clamp(L.r * Math.sqrt(k / L.v.k), L.r * 0.6, 2.2);
      c.setTransform(d, 0, 0, d, 0, 0); c.globalAlpha = 1;
      c.fillStyle = this.opts.landColor || "#3a3a3c";
      c.beginPath();
      for (let i = 0; i < P.length; i += 2) {
        const x = (P[i] - v.cx) * k + W / 2, y = (P[i + 1] - v.cy) * k + H / 2;
        if (x < -3 || x > W + 3 || y < -3 || y > H + 3) continue;
        c.moveTo(x + r, y); c.arc(x, y, r, 0, Math.PI * 2);
      }
      c.fill();
    }
    _scratch(name) {  // canvas de travail réutilisés (taille du canvas principal)
      this.scr_ = this.scr_ || {};
      let c = this.scr_[name];
      if (!c || c.width !== this.canvas.width || c.height !== this.canvas.height) {
        c = this.scr_[name] = document.createElement("canvas");
        c.width = this.canvas.width; c.height = this.canvas.height;
      }
      return c;
    }
    // masque : rectangle (coordonnées écran) opaque au centre, bords en dégradé sur « f » px
    _mask(x, y, w, h, f) {
      const c = this._scratch("mask"), m = c.getContext("2d"), d = this.dpr;
      m.setTransform(d, 0, 0, d, 0, 0); m.globalAlpha = 1;
      m.globalCompositeOperation = "source-over";
      m.clearRect(0, 0, this.W, this.H);
      const grad = (a0, len, horiz) => {
        const g = horiz ? m.createLinearGradient(a0, 0, a0 + len, 0) : m.createLinearGradient(0, a0, 0, a0 + len);
        const fr = clamp(f / len, 0.001, 0.5);
        g.addColorStop(0, "rgba(0,0,0,0)"); g.addColorStop(fr, "#000"); g.addColorStop(1 - fr, "#000"); g.addColorStop(1, "rgba(0,0,0,0)");
        return g;
      };
      m.fillStyle = grad(x, w, true); m.fillRect(0, 0, this.W, this.H);
      m.globalCompositeOperation = "destination-in";
      m.fillStyle = grad(y, h, false); m.fillRect(0, 0, this.W, this.H);
      m.globalCompositeOperation = "source-over";
      return c;
    }
    _frame(dt) {
      const ctx = this.ctx, W = this.W, H = this.H, sc = this.sc, R = this.reduced, d = this.dpr;
      if (!W || !this.view) return false;
      this.clock += dt;
      let busy = false;
      // transition de cadrage (zoom log-linéaire)
      if (this.vTo) {
        this.vT = Math.min(1, this.vT + dt / 0.9);
        const e = easeInOut(this.vT), a = this.vFrom, b = this.vTo;
        this.view = { k: Math.exp(Math.log(a.k) + (Math.log(b.k) - Math.log(a.k)) * e), cx: a.cx + (b.cx - a.cx) * e, cy: a.cy + (b.cy - a.cy) * e };
        if (this.vT >= 1) { this.view = b; this.vFrom = this.vTo = null; }
        busy = true;
      }
      const v = this.view, k = v.k, iz = 1 / k;
      // avancement du zoom t (0 = Monde, 1 = Europe). Pendant un zoom, la grille fine occupe un rectangle aux bords
      // adoucis (masque) et la grille monde est évidée dessous : la carte reste continue, sans double trame.
      const LE = this.layerE, LW = this.layerW;
      const t = LE ? clamp(Math.log(k) / Math.log(LE.v.k), 0, 1) : 0;
      const sm = (x) => { x = clamp(x, 0, 1); return x * x * (3 - 2 * x); };
      ctx.setTransform(d, 0, 0, d, 0, 0);
      ctx.globalAlpha = 1;
      ctx.clearRect(0, 0, W, H);
      if (!LE || t < 0.001) this._drawLayer(LW, 1);
      else if (t > 0.999 || !LW) this._drawLayer(LE, 1);
      else {
        const fe = sm(t / 0.3), s = k / LE.v.k, w = s * W, h = s * H;
        const m = this._mask(W / 2 - w / 2 + (LE.v.cx - v.cx) * k, H / 2 - h / 2 + (LE.v.cy - v.cy) * k, w, h, Math.min(w, h) * 0.16 * (1 - t) + 1);
        this._drawLayer(LE, fe);
        ctx.setTransform(1, 0, 0, 1, 0, 0); ctx.globalAlpha = 1;
        ctx.globalCompositeOperation = "destination-in"; ctx.drawImage(m, 0, 0);
        const tc = this._scratch("tmp"), tx = tc.getContext("2d");
        tx.setTransform(1, 0, 0, 1, 0, 0); tx.globalCompositeOperation = "source-over"; tx.globalAlpha = 1;
        tx.clearRect(0, 0, tc.width, tc.height);
        this._drawDots(LW, tx);   // trame monde redessinée en vectoriel (pas de bitmap agrandi flou)
        tx.setTransform(1, 0, 0, 1, 0, 0); tx.globalCompositeOperation = "destination-out"; tx.globalAlpha = fe; tx.drawImage(m, 0, 0);
        tx.globalCompositeOperation = "source-over";
        ctx.globalCompositeOperation = "destination-over"; ctx.drawImage(tc, 0, 0);
        ctx.globalCompositeOperation = "source-over";
      }
      const fw = 1 - sm(t / 0.5), fe = sm((t - 0.5) / 0.5);   // dosage des teintes par grille
      // le reste se dessine en coordonnées base (tailles divisées par k : constantes à l'écran)
      ctx.setTransform(d * k, 0, 0, d * k, d * (W / 2 - v.cx * k), d * (H / 2 - v.cy * k));
      const focus = this.hoverKey || this.hlKey;
      const kk = R ? 1 : 1 - Math.exp(-dt * 7);
      const live = [];
      for (const s of [...this.sites.values()]) {
        const ka = R ? 1 : 1 - Math.exp(-dt * (s.target ? 3 : 4.5));
        s.alpha += (s.target - s.alpha) * ka;
        if (s.target) s.reveal = R ? 1 : Math.min(1, s.reveal + dt / (s.local ? 0.9 : 1.15));
        const rT = s.conR * sc;
        s.r += (rT - s.r) * kk;
        const m = s.members.some((w) => this._match(w));
        const dT = (m ? 1 : 0.13) * (focus && focus !== s.key ? 0.38 : 1);
        s.dim += (dT - s.dim) * kk;
        if (!s.target && s.alpha < 0.01) { this.sites.delete(s.key); continue; }
        if (Math.abs(s.target - s.alpha) > 0.01 || s.reveal < 1 || Math.abs(dT - s.dim) > 0.01 || Math.abs(rT - s.r) > 0.05) busy = true;
        live.push(s);
      }
      // points de terre teintés autour des destinations
      if (this.opts.tint !== false) {
        for (const [L, la] of [[this.layerW, fw], [this.layerE, fe]]) {
          if (!L || la < 0.02) continue;
          const rr = L.r / L.v.k;
          for (const s of live) {
            if (s.local) continue;  // pas de teinte autour du domicile
            const a = s.alpha * s.dim * easeOut(s.reveal) * la;
            if (a < 0.01) continue;
            const tp = this._tint(s, L);
            ctx.fillStyle = s.color;
            for (let i = 0; i < tp.length; i += 3) {
              ctx.globalAlpha = a * tp[i + 2] * 0.55;
              ctx.beginPath(); ctx.arc(tp[i], tp[i + 1], rr * 1.05, 0, Math.PI * 2); ctx.fill();
            }
          }
        }
      }
      // arcs (le lieu survolé en dernier)
      live.sort((a, b) => (a.key === focus) - (b.key === focus) || a.dim - b.dim);
      const ringR = 11.5 * sc * iz;
      for (const s of live) {
        const a = s.alpha * s.dim, on = s.key === focus;
        if (a < 0.005) continue;
        ctx.globalAlpha = a;
        ctx.lineWidth = (on ? 1.8 : 1.15) * Math.max(1, sc * 0.95) * iz;
        ctx.lineCap = "round";
        const rv = easeOut(s.reveal);
        if (s.local) {
          ctx.strokeStyle = rgba(s.color, on ? 0.95 : 0.7);
          ctx.beginPath(); ctx.arc(this.hx, this.hy, ringR, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * rv); ctx.stroke();
          continue;
        }
        const g = ctx.createLinearGradient(s.xs[0], s.ys[0], s.x, s.y);
        g.addColorStop(0, rgba(s.color, on ? 0.35 : 0.12)); g.addColorStop(1, rgba(s.color, on ? 1 : 0.8));
        ctx.strokeStyle = g;
        const end = s.len * rv;
        ctx.beginPath(); ctx.moveTo(s.xs[0], s.ys[0]);
        for (let i = 1; i < s.cum.length && s.cum[i - 1] < end; i++) {
          if (s.cum[i] <= end) ctx.lineTo(s.xs[i], s.ys[i]);
          else { const p = this._at(s, end); ctx.lineTo(p[0], p[1]); }
        }
        ctx.stroke();
      }
      // points voyageurs : densité ∝ log(connexions), vitesse constante à l'écran
      if (!R) {
        busy = true;
        const rr = 1.35 * Math.max(0.85, sc) * iz, tail = 13 * sc * iz;
        for (const s of live) {
          const a = s.alpha * s.dim;
          if (s.rank >= 40) continue;   // allège le rendu si beaucoup de destinations
          const n = clamp(Math.round(1 + 1.3 * Math.log10(s.conns + 1)), 1, 6);
          if (s.local) {
            s.ph += dt / 4.5;
            if (s.reveal < 1 || a < 0.02) continue;
            ctx.fillStyle = s.color; ctx.globalAlpha = a;
            for (let j = 0; j < n; j++) {
              const ang = -Math.PI / 2 + Math.PI * 2 * frac(s.ph + j / n + s.seed);
              ctx.beginPath(); ctx.arc(this.hx + Math.cos(ang) * ringR, this.hy + Math.sin(ang) * ringR, rr, 0, Math.PI * 2); ctx.fill();
            }
            continue;
          }
          s.ph += dt / clamp((s.len * k) / (W * 0.06), 1.8, 7.5);
          if (s.reveal < 1 || a < 0.02) continue;
          ctx.fillStyle = s.color; ctx.strokeStyle = s.color; ctx.lineWidth = rr * 1.1;
          for (let j = 0; j < n; j++) {
            const t = frac(s.ph + j / n + s.seed), dd = t * s.len;
            const fa = Math.pow(Math.sin(Math.PI * t), 0.7) * a;
            const p = this._at(s, dd);
            for (let q = 0; q < 3; q++) {   // traîne courte en 3 segments dégressifs (pas de flou)
              const p0 = this._at(s, dd - (tail * (q + 1)) / 3), p1 = q ? this._at(s, dd - (tail * q) / 3) : p;
              ctx.globalAlpha = fa * (0.45 - q * 0.14);
              ctx.beginPath(); ctx.moveTo(p0[0], p0[1]); ctx.lineTo(p1[0], p1[1]); ctx.stroke();
            }
            ctx.globalAlpha = fa;
            ctx.beginPath(); ctx.arc(p[0], p[1], rr, 0, Math.PI * 2); ctx.fill();
          }
        }
      }
      // pastilles (grandes d'abord)
      const pins = live.filter((s) => !s.local).sort((a, b) => b.r - a.r);
      for (const s of pins) {
        const pop = clamp((s.reveal - 0.72) / 0.28, 0, 1);
        const r = s.r * easeOut(pop) * iz, a = s.alpha * s.dim, on = s.key === focus;
        if (r * k < 0.3 || a < 0.01) continue;
        if (!R && (s.risk === "eleve" || s.isNew)) {
          const ph = frac(this.clock / 2.8 + s.seed);
          ctx.globalAlpha = a * 0.5 * (1 - ph); ctx.strokeStyle = s.color; ctx.lineWidth = iz;
          ctx.beginPath(); ctx.arc(s.x, s.y, r + (2 + 13 * sc * easeOut(ph)) * iz, 0, Math.PI * 2); ctx.stroke();
        }
        ctx.globalAlpha = a;
        ctx.strokeStyle = rgba(s.color, on ? 0.7 : 0.32); ctx.lineWidth = iz;
        ctx.beginPath(); ctx.arc(s.x, s.y, r + 3 * sc * iz, 0, Math.PI * 2); ctx.stroke();
        ctx.fillStyle = s.color; ctx.strokeStyle = "#000"; ctx.lineWidth = 1.5 * iz;
        ctx.beginPath(); ctx.arc(s.x, s.y, r, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      }
      // domicile
      const home = this.data ? this.data.home : { lat: 48.86, lon: 2.35 };
      const [hx, hy] = this.proj(home.lon, home.lat);
      this.hx = hx; this.hy = hy;
      if (!R) {
        const ph = frac(this.clock / 3.4);
        ctx.globalAlpha = 0.45 * (1 - ph); ctx.strokeStyle = HOME_C; ctx.lineWidth = iz;
        ctx.beginPath(); ctx.arc(hx, hy, (4 + 15 * easeOut(ph)) * sc * iz, 0, Math.PI * 2); ctx.stroke();
      }
      ctx.globalAlpha = 1;
      ctx.strokeStyle = rgba(HOME_C, this.hoverKey === "home" ? 0.9 : 0.5); ctx.lineWidth = iz;
      ctx.beginPath(); ctx.arc(hx, hy, 7 * sc * iz, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = HOME_C; ctx.strokeStyle = "#000"; ctx.lineWidth = 1.5 * iz;
      ctx.beginPath(); ctx.arc(hx, hy, 3.6 * sc * iz, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      // textes en coordonnées écran
      ctx.setTransform(d, 0, 0, d, 0, 0);
      const placed = k > 1.3 ? this._edges(pins, focus) : [];
      this._labels(pins, focus, placed);
      ctx.globalAlpha = 1;
      return busy;
    }
    // étiquettes discrètes des lieux principaux (évitement de chevauchement simple)
    _labels(pins, focus, placed) {
      if (this.W < 640 && this.view.k < 1.3) return;
      const ctx = this.ctx, W = this.W, H = this.H;
      const [hx, hy] = this.scr(this.hx, this.hy);
      placed.push([hx - 12, hy - 12, 24, 24]);
      const fs = Math.round(10.5 * clamp(this.sc, 0.95, 1.12) * 10) / 10;
      ctx.font = `500 ${fs}px ${FONT}`;
      ctx.textBaseline = "middle";
      const P = pins.map((s) => { const [x, y] = this.scr(s.x, s.y); return { s, x, y }; }).filter((p) => p.x > -4 && p.x < W + 4 && p.y > -4 && p.y < H + 4);
      for (const p of P) placed.push([p.x - p.s.r - 3, p.y - p.s.r - 3, 2 * p.s.r + 6, 2 * p.s.r + 6]);
      const cand = P.filter((p) => p.s.alpha > 0.4 && p.s.reveal > 0.9 && p.s.label)
        .sort((a, b) => (b.s.key === focus) - (a.s.key === focus) || RISK_RANK[b.s.risk] - RISK_RANK[a.s.risk] || b.s.conns - a.s.conns)
        .slice(0, W < 640 ? 5 : this.view.k > 1.3 ? 14 : 8);
      const hit = (r) => placed.some((q) => r[0] < q[0] + q[2] && r[0] + r[2] > q[0] && r[1] < q[1] + q[3] && r[1] + r[3] > q[1]);
      for (const { s, x, y } of cand) {
        const txt = s.label + (s.members.length > 1 ? `  ·  ${s.members.length}` : "");
        const w = ctx.measureText(txt).width, off = s.r + 6 * this.sc;
        const spots = [[x + off, y - fs / 2 - 1], [x - off - w, y - fs / 2 - 1], [x - w / 2, y - off - fs - 2], [x - w / 2, y + off]];
        const spot = spots.find(([sx, sy]) => sx > 4 && sx + w < W - 4 && sy > 2 && sy + fs < H - 2 && !hit([sx - 2, sy - 1, w + 4, fs + 2]));
        if (!spot) continue;
        placed.push([spot[0] - 2, spot[1] - 1, w + 4, fs + 2]);
        ctx.globalAlpha = s.alpha * Math.max(s.dim, 0.25);
        ctx.fillStyle = s.key === focus ? "#ffffff" : "#98989f";
        ctx.fillText(txt, spot[0], spot[1] + fs / 2 + 0.5);
      }
    }
    // vue zoomée : repère au bord pour les destinations hors cadre (là où l'arc sort)
    _edges(pins, focus) {
      const ctx = this.ctx, W = this.W, H = this.H, m = 10;
      const fs = 10.5;
      ctx.font = `500 ${fs}px ${FONT}`;
      ctx.textBaseline = "middle";
      const used = [];
      for (const s of pins.slice().sort((a, b) => RISK_RANK[b.risk] - RISK_RANK[a.risk] || b.conns - a.conns)) {
        if (s.reveal < 1 || s.alpha < 0.3) continue;
        const [ex, ey] = this.scr(s.x, s.y);
        if (ex > m && ex < W - m && ey > m && ey < H - m) continue;
        let px = null, py = null;
        for (let i = 1; i < s.xs.length; i++) {
          const [x, y] = this.scr(s.xs[i], s.ys[i]);
          if (x < m || x > W - m || y < m || y > H - m) {
            const [x0, y0] = this.scr(s.xs[i - 1], s.ys[i - 1]);
            const t = Math.min(x < m ? (m - x0) / (x - x0) : x > W - m ? (W - m - x0) / (x - x0) : 1, y < m ? (m - y0) / (y - y0) : y > H - m ? (H - m - y0) / (y - y0) : 1);
            px = x0 + (x - x0) * clamp(t, 0, 1); py = y0 + (y - y0) * clamp(t, 0, 1);
            break;
          }
        }
        if (px == null) continue;
        const txt = `${s.label} ›`, w = ctx.measureText(txt).width;
        const right = px > W - m - 1, left = px < m + 1, top = py < m + 1;
        let tx = right ? px - w - 8 : left ? px + 8 : px - w / 2;
        let ty = top ? py + 12 : py > H - m - 1 ? py - 12 : py;
        tx = clamp(tx, 4, W - w - 4); ty = clamp(ty, 8, H - 8);
        const box = [tx - 2, ty - fs / 2 - 2, w + 4, fs + 4];
        if (used.some((u) => box[0] < u[0] + u[2] && box[0] + box[2] > u[0] && box[1] < u[1] + u[3] && box[1] + box[3] > u[1])) continue;
        used.push(box);
        const a = s.alpha * Math.max(s.dim, 0.25);
        ctx.globalAlpha = a; ctx.fillStyle = s.color;
        ctx.beginPath(); ctx.arc(px, py, 2.2, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = s.key === focus ? "#ffffff" : "#98989f";
        ctx.fillText(txt, tx, ty);
      }
      return used;
    }

    /* ----- interactions ----- */
    _hit(sx, sy) {
      const v = this.view;
      if (!v) return null;
      const iz = 1 / v.k, x = (sx - this.W / 2) * iz + v.cx, y = (sy - this.H / 2) * iz + v.cy;
      let best = null, bd = Infinity;
      for (const s of this.sites.values()) {
        if (s.target !== 1 || s.alpha < 0.3 || s.local) continue;
        const d = Math.hypot(x - s.x, y - s.y);
        if (d < Math.max(s.r + 6, 9) * iz && d < bd) { bd = d; best = s.key; }
      }
      if (best) return best;
      if (this.hx != null && Math.hypot(x - this.hx, y - this.hy) < (8 * this.sc + 2) * iz) return "home";
      const loc = this.sites.get("local");
      if (loc && loc.target && Math.abs(Math.hypot(x - this.hx, y - this.hy) - 11.5 * this.sc * iz) < 4.5 * iz) return "local";
      for (const s of this.sites.values()) {
        if (s.target !== 1 || s.alpha < 0.3 || s.local || !s.xs) continue;
        for (let i = 1; i < s.xs.length; i++) {
          const ax = s.xs[i - 1], ay = s.ys[i - 1], vx = s.xs[i] - ax, vy = s.ys[i] - ay, l2 = vx * vx + vy * vy || 1;
          const t = clamp(((x - ax) * vx + (y - ay) * vy) / l2, 0, 1);
          const d = Math.hypot(x - ax - vx * t, y - ay - vy * t);
          if (d < 5 * iz && d < bd) { bd = d; best = s.key; }
        }
      }
      return best;
    }
    _pos(e) { const r = this.canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; }
    _onMove(e) {
      if (e.pointerType === "touch") return;
      const [x, y] = this._pos(e);
      const key = this._hit(x, y);
      if (key !== this.hoverKey) { this.hoverKey = key; this._kick(); }
      this.canvas.style.cursor = key && key !== "home" ? "pointer" : "";
      if (key) this._showTip(this._tipFor(key), e.clientX, e.clientY);
      else this._hideTip();
    }
    _onLeave(e) {
      if (e && e.pointerType === "touch") return;   // tactile : l'info-bulle du tap reste ouverte
      this.hoverKey = null; this._hideTip(); this.canvas.style.cursor = ""; this._kick(); }
    _onClick(e) {
      const [x, y] = this._pos(e);
      const key = this._hit(x, y);
      if (e.pointerType === "touch" || !matchMedia("(hover: hover)").matches) {  // mobile : le tap montre l'info-bulle
        this.hoverKey = key; this._kick();
        if (key) this._showTip(this._tipFor(key), e.clientX, e.clientY); else this._hideTip();
      }
      const s = key && this.sites.get(key);
      if (s && this.opts.onSelect) this.opts.onSelect(s.members[0].d, { key: s.key, label: s.label, dests: s.members.map((w) => w.d), conns: s.conns, risk: s.risk });
    }
    _onLegend(e) {
      const b = e.target.closest("button");
      if (!b) return;
      if (b.dataset.view) { this.setView(b.dataset.view); return; }
      if (b.dataset.mode) { this.setColorBy(b.dataset.mode); return; }
      const dim = this.colorBy === "category" ? "category" : "risk", v = b.dataset.v;
      if (!v) return;
      this.setFilter(Object.assign({}, this.filter, { [dim]: this.filter[dim] === v ? null : v }));
      if (this.opts.onFilter) this.opts.onFilter(Object.assign({}, this.filter));
    }
    _tipFor(key) {
      if (key === "home") {
        const h = this.data ? this.data.home : { label: "Domicile" };
        const ds = this.data ? this.data.dests : [];
        const tot = ds.reduce((t, w) => t + w.conns, 0), eu = ds.filter((w) => w.d.eu).reduce((t, w) => t + w.conns, 0);
        const row = (k, v) => `<div class="wm-tt-r"><span>${k}</span><span>${v}</span></div>`;
        return `<div class="wm-tt"><div class="wm-tt-h"><i style="background:${HOME_C}"></i>${esc(h.label || "Domicile")}</div><div class="wm-tt-s"></div>` +
          (h.ip ? row("IP publique", `<span class="wm-mono">${esc(h.ip)}</span>`) : "") +
          row("Destinations", nf.format(ds.length)) + row("Connexions", nf.format(tot)) +
          (tot ? row("Part vers l'UE", `${Math.round((eu / tot) * 100)} %`) : "") + `</div>`;
      }
      const s = this.sites.get(key);
      if (!s) return "";
      const [top, ...more] = s.members;
      return tipHtml(top, more, s.local);
    }
    _showTip(html, x, y) {
      if (typeof window.showTip === "function" && document.getElementById("tip")) { window.showTip(html, x, y); this.tipMode = "core"; return; }
      let t = this.tipEl || document.querySelector(".wm-tip");
      if (!t) { t = document.createElement("div"); t.className = "wm-tip"; document.body.appendChild(t); }
      this.tipEl = t; this.tipMode = "own";
      t.innerHTML = html; t.classList.add("on");
      const r = t.getBoundingClientRect();
      let nx = x + 16, ny = y + 14;
      if (nx + r.width > innerWidth - 8) nx = x - r.width - 16;
      if (ny + r.height > innerHeight - 8) ny = y - r.height - 14;
      t.style.left = Math.max(8, nx) + "px"; t.style.top = Math.max(8, ny) + "px";
    }
    _hideTip() {
      if (this.tipMode === "core") { if (typeof hideTip === "function") hideTip(); else { const t = document.getElementById("tip"); t && t.classList.remove("on"); } }
      else if (this.tipEl) this.tipEl.classList.remove("on");
      this.tipMode = null;
    }

    /* ----- légende et résumé ----- */
    _legend() {
      this.legendEl.querySelectorAll("[data-view]").forEach((b) => b.classList.toggle("on", b.dataset.view === this.mode));
      this.legendEl.querySelectorAll("[data-mode]").forEach((b) => b.classList.toggle("on", b.dataset.mode === this.colorBy));
      const dim = this.colorBy === "category" ? "category" : "risk";
      let items;
      if (dim === "risk") items = Object.entries(RISK);
      else {
        const present = new Set(this.data ? this.data.dests.map((w) => w.cat) : []);
        items = Object.entries(CAT).filter(([kk]) => !this.data || present.has(kk));
      }
      const act = this.filter[dim];
      this.itemsEl.classList.toggle("f", !!act);
      const html = `<span class="wm-it home" style="--c:${HOME_C}"><i></i>${esc((this.data && this.data.home.label) || "Domicile")}</span>` +
        items.map(([kk, [c, l]]) => `<button class="wm-it${act === kk ? " on" : ""}" data-v="${kk}" style="--c:${c}" aria-pressed="${act === kk}" title="Filtrer : ${esc(l)}"><i></i>${esc(l)}</button>`).join("");
      if (html !== this.legendHtml) this.itemsEl.innerHTML = this.legendHtml = html;
    }
    _summary() {
      const ds = this.data ? this.data.dests : [];
      this.emptyEl.hidden = ds.length > 0;
      this.emptyEl.textContent = "Aucun flux sortant observé pour l'instant";
      if (!ds.length) { this.sumEl.innerHTML = ""; return; }
      const tot = ds.reduce((t, w) => t + w.conns, 0), eu = ds.filter((w) => w.d.eu).reduce((t, w) => t + w.conns, 0);
      const pays = new Set(ds.map((w) => w.d.country).filter(Boolean)).size;
      const unk = ds.filter((w) => !w.loc).length;
      this.sumEl.innerHTML = `<b>${nf.format(ds.length)}</b> destinations · <b>${pays}</b> pays · <b>${Math.round((eu / (tot || 1)) * 100)} %</b> des connexions dans l'UE` +
        (unk ? ` · ${unk} non localisée${unk > 1 ? "s" : ""}` : "");
    }
  }

  WorldMap.RISK = RISK;
  WorldMap.CAT = CAT;
  WorldMap.tipHtml = (dest) => tipHtml({ d: dest, risk: dest.risk, cat: dest.category });
  WorldMap.blockLabel = blockLabel;
  WorldMap.RATIO = RATIO;
  window.WorldMap = WorldMap;
})();
