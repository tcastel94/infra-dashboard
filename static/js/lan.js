/* InfraDash — réseau local (scan, fiches d'appareils), ports, architecte IA, exécution sécurisée des corrections.
   Chargé après views.js : étend VIEWS / RENDER sans les modifier. Tout texte dynamique passe par esc(). */
"use strict";
(function () {
  const ICONS = ["server", "nas", "pc", "laptop", "phone", "tablet", "watch", "tv", "speaker", "camera", "printer", "bulb", "plug", "thermo", "gamepad", "router", "wifi", "lock", "home", "cloud", "claw", "unknown"];
  const ICON_LBL = { server: "Serveur", nas: "NAS", pc: "PC fixe", laptop: "Portable", phone: "Téléphone", tablet: "Tablette", watch: "Montre", tv: "TV / ampli", speaker: "Enceinte", camera: "Caméra", printer: "Imprimante", bulb: "Éclairage", plug: "Prise / objet", thermo: "Capteur", gamepad: "Console", router: "Réseau", wifi: "Borne Wi-Fi", lock: "Serrure", home: "Domotique", cloud: "Cloud", claw: "Agent", unknown: "Inconnu" };
  const CATS = ["Réseau", "Multimédia", "Maison connectée", "Mobiles", "Ordinateurs & serveurs", "Autres"];
  const LINK = { wired: "Ethernet", wifi: "Wi-Fi", unknown: "Liaison ?" };
  const now = () => Date.now() / 1000;
  const inv = () => (SL().lan_inventory || {}).devices || [];
  const fmtMbps = (m) => (m >= 1000 ? nf1.format(m / 1000) + " Gb/s" : nf0.format(m) + " Mb/s");
  const get = async (u) => (await fetch(u, { cache: "no-store" })).json();
  const toast = (el, txt, bad) => { if (!el) return; el.textContent = txt; el.style.color = bad ? "var(--crit)" : ""; };

  /* nouvelle source pour le schéma « Réseau local » et l'ancienne vue : l'inventaire fusionné, repli sur l'ancien état */
  window.lanDevices = () => (inv().length ? inv() : (SL().lan_devices || {}).devices || []);

  VIEWS.splice(VIEWS.findIndex((v) => v[0] === "lan") + 1, 0, ["ports", "Ports", "ports"]);
  VIEWS.splice(VIEWS.findIndex((v) => v[0] === "ai") + 1, 0, ["architect", "Architecte", "compass"]);
  SUBS.ports = "Ports utilisés et libres du NAS Unraid, du homelab et de clawhost";
  SUBS.architect = "Incohérences détectées et plan d'architecture proposé par l'IA locale";
  SUBS.lan = "Scanner le réseau, nommer les appareils, voir leur liaison Ethernet / Wi-Fi";

  /* ============================================================ RÉSEAU LOCAL */
  const LU = { f: "all", q: "", sel: null, polling: false };
  const baseRenderLan = RENDER.lan;

  function devIcon(d, big) {
    const bad = lanBad().has(d.mac) || (d.ports || []).some((p) => p.risk);
    const cls = !d.alive ? "" : bad ? "crit" : d.is_new ? "warn" : d.known ? "ok" : "warn";
    return `<span class="dev-ico ${cls}">${icon(d.icon || "unknown")}<i class="dot ${d.alive ? "ok" : ""}"></i></span>`;
  }
  function linkTag(d) {
    const lk = d.link || {}, t = lk.type || "unknown";
    const bits = [LINK[t]];
    if (lk.speed_mbps) bits.push(fmtMbps(lk.speed_mbps));
    else if (d.rtt && d.rtt.avg != null && d.alive) bits.push(nf1.format(d.rtt.avg) + " ms");
    return `<span class="tag ${t === "wired" ? "ok" : t === "wifi" ? "info" : "mute"}" title="${esc((lk.evidence || []).join(" · ") || "indices insuffisants")}">${icon(t === "wired" ? "cable" : t === "wifi" ? "wifi" : "unknown")}${esc(bits.join(" · "))}</span>`;
  }
  function devCard(d) {
    const bad = lanBad().has(d.mac), risky = (d.ports || []).some((p) => p.risk);
    return `<button class="dev-card ${d.alive ? "" : "off"} ${d.is_new ? "is-new" : ""} ${bad ? "bad" : ""}" data-mac="${esc(d.mac)}">${devIcon(d)}
      <div style="min-width:0"><div class="dev-name">${esc(d.name)}</div><div class="dev-sub">${esc(d.ip || "—")}${d.vendor && d.vendor !== d.name ? " · " + esc(d.vendor) : ""}</div>
      <div class="dev-tags">${d.alive ? linkTag(d) : '<span class="tag mute">hors ligne</span>'}${d.is_new ? '<span class="tag warn">nouveau</span>' : ""}${d.trusted ? '<span class="tag ok">de confiance</span>' : ""}${risky ? '<span class="tag crit">port à risque</span>' : ""}${bad ? '<span class="tag crit">CVE</span>' : ""}</div></div></button>`;
  }
  function lanScanLine() {
    const sc = SL().lan_scan || {}, li = SL().lan_inventory || {};
    if (sc.status === "en_cours") return "";
    const l = sc.last;
    return l ? `Dernier scan ${ago(l.t)} : ${l.alive} présents${l.new && l.new.length ? `, ${l.new.length} nouveau(x)` : ""}, ${fmtDur(l.duration_s)}${l.deep ? " avec ports" : ""}.`
      : li.scan_t ? `Dernier scan ${ago(li.scan_t)}.` : "Aucun scan depuis le démarrage.";
  }
  function renderProgress() {
    const sc = SL().lan_scan || {}, p = sc.progress;
    const busy = sc.status === "en_cours";
    const btn = $("#lan-scan-btn");
    btn.disabled = busy; btn.innerHTML = busy ? '<span class="ai-spin"></span> Scan en cours…' : `${icon("scan")}Scanner le réseau`;
    setHTML($("#lan-progress"), busy ? `<div class="lan-prog"><span>${esc((p && p.phase) || "démarrage")}${p && p.total ? ` ${p.done}/${p.total}` : ""}</span><div class="bar"><i style="width:${p && p.total ? Math.round((100 * p.done) / p.total) : 5}%"></i></div></div>` : "");
    const m = $("#lan-scan-msg"); if (!LU.msg || now() - LU.msgT > 12) m.textContent = lanScanLine(); else m.textContent = LU.msg;
  }
  async function pollScan() {
    if (LU.polling) return; LU.polling = true;
    try {
      for (let i = 0; i < 120; i++) {
        const sc = await get("/api/lan/scan");
        S.slow.lan_scan = sc; if (CURRENT === "lan") renderProgress();
        if (sc.status !== "en_cours") break;
        await new Promise((r) => setTimeout(r, 1500));
      }
      S.slow.lan_inventory = await get("/api/lan/inventory");
      if (CURRENT === "lan") renderLan2();
      if (LU.sel) openDevice(LU.sel, true);
    } catch (e) { /* le flux reprendra */ }
    LU.polling = false;
  }
  async function doScan() {
    LU.msg = "Lancement…"; LU.msgT = now(); renderProgress();
    try {
      const r = await postJSON("/api/lan/scan", { deep: $("#lan-deep").checked });
      LU.msg = r.message; LU.msgT = now();
      if (r.accepted) { S.slow.lan_scan = Object.assign({}, S.slow.lan_scan, { status: "en_cours", progress: { phase: "démarrage", done: 0, total: 254 } }); pollScan(); }
    } catch (e) { LU.msg = "Échec de la demande de scan."; LU.msgT = now(); }
    renderProgress();
  }
  function lanFilter(list) {
    const q = LU.q.trim().toLowerCase();
    let out = list;
    if (LU.f === "all") out = out.filter((d) => d.alive);
    else if (LU.f === "new") out = out.filter((d) => d.is_new);
    else if (LU.f === "todo") out = out.filter((d) => d.alive && !d.known);
    else if (LU.f === "wifi") out = out.filter((d) => d.alive && d.link.type === "wifi");
    else if (LU.f === "wired") out = out.filter((d) => d.alive && d.link.type === "wired");
    else if (LU.f === "off") out = out.filter((d) => !d.alive);
    if (q) out = out.filter((d) => [d.name, d.ip, d.mac, d.vendor, d.hostname, d.cat, d.note].some((x) => String(x || "").toLowerCase().includes(q)));
    return out;
  }
  function renderLan2(first) {
    if (!$("#lan-scan-btn").dataset.init) {
      $("#lan-scan-btn").dataset.init = 1;
      $("#lan-scan-btn").addEventListener("click", doScan);
      $("#ns-filter").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { LU.f = b.dataset.f; renderLan2(); } });
      $("#lan-search").addEventListener("input", (e) => { LU.q = e.target.value; renderLan2(); });
      $("#ns-devices").addEventListener("click", (e) => { const c = e.target.closest("[data-mac]"); if (c) openDevice(c.dataset.mac); });
    }
    baseRenderLan(first);
    const all = inv();
    if (!all.length) { setHTML($("#ns-devices"), '<div class="empty">Inventaire en cours de construction (premier scan dans quelques secondes)…</div>'); renderProgress(); return; }
    const live = all.filter((d) => d.alive), lc = (SL().lan_inventory || {}).link_counts || {}, bad = lanBad();
    const dg = (SL().netscan || {}).digest || {};
    setHTML($("#ns-kpis"), [
      ["Appareils présents", nf0.format(live.length), `${all.length - live.length} connus hors ligne`, "var(--teal)"],
      ["Nouveaux", nf0.format(all.filter((d) => d.is_new).length), "jamais vus avant, à valider", all.some((d) => d.is_new) ? "var(--warn)" : "var(--ok)"],
      ["Ethernet / Wi-Fi", `${nf0.format(lc.wired || 0)} / ${nf0.format(lc.wifi || 0)}`, `${nf0.format(lc.unknown || 0)} liaison(s) indéterminée(s)`, "var(--blue)"],
      ["À identifier", nf0.format(live.filter((d) => !d.known).length), "sans nom validé ni confiance", live.some((d) => !d.known) ? "var(--warn)" : "var(--ok)"],
      ["Alertes", nf0.format(new Set([...bad, ...live.filter((d) => (d.ports || []).some((p) => p.risk)).map((d) => d.mac)]).size), `${nf0.format((dg.active || []).length)} CVE confirmée(s) · ports à risque`, bad.size ? "var(--crit)" : "var(--ok)"],
    ].map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
    const list = lanFilter(all);
    $("#ns-dev-sub").textContent = `${list.length} / ${all.length}`;
    const fam = {}; list.forEach((d) => (fam[d.cat] = fam[d.cat] || []).push(d));
    setHTML($("#ns-devices"), Object.keys(fam).length ? `<div class="dev-fams">${Object.entries(fam).sort((a, b) => b[1].length - a[1].length).map(([c, ds]) =>
      `<div class="dev-fam"><div class="lbl">${esc(c)} · ${ds.length}</div><div class="dev-grid">${ds.map(devCard).join("")}</div></div>`).join("")}</div>` : '<div class="empty">Aucun appareil pour ce filtre</div>');
    renderProgress();
  }
  RENDER.lan = renderLan2;

  /* ---------- fiche d'un appareil ---------- */
  function ensureDrawer() {
    if ($("#drawer")) return;
    document.body.insertAdjacentHTML("beforeend", '<div class="drawer-back" id="drawer-back" hidden></div><aside class="drawer" id="drawer" role="dialog" aria-modal="true" aria-label="Fiche appareil" hidden></aside>');
    $("#drawer-back").addEventListener("click", closeDevice);
    addEventListener("keydown", (e) => { if (e.key === "Escape") { if ($(".rem-back")) closeRem(); else closeDevice(); } });
    $("#drawer").addEventListener("click", onDrawerClick);
  }
  function closeDevice() { LU.sel = null; const d = $("#drawer"); if (!d) return; d.classList.remove("on"); $("#drawer-back").classList.remove("on"); setTimeout(() => { if (!LU.sel) { d.hidden = true; $("#drawer-back").hidden = true; } }, 200); }
  function openDevice(mac, keep) {
    ensureDrawer();
    const d = inv().find((x) => x.mac === mac); if (!d) return;
    if (keep && $("#drawer").contains(document.activeElement) && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) return;
    LU.sel = mac; LU.icon = d.icon;
    const lk = d.link || {}, cl = ((S.topology || {}).clients || []).find((c) => c.ip === d.ip);
    const dg = ((SL().netscan || {}).digest || {}).active || [];
    const cves = dg.filter((g) => g.mac === mac);
    const rtt = d.rtt || {};
    const dr = $("#drawer");
    dr.innerHTML = `<div class="dr-head">${devIcon(d)}<div><h2>${esc(d.name)}</h2><div class="cell-sub mono">${esc(d.ip || "—")} · ${d.alive ? "en ligne" : "hors ligne"}</div></div><button class="dr-x" data-close aria-label="Fermer">×</button></div>
    <h3>Identité</h3>
    <div class="fld"><label for="dv-name">Nom</label><input type="text" id="dv-name" maxlength="48" value="${esc(d.custom_name ? d.name : "")}" placeholder="${esc(d.auto_name || d.name)}"></div>
    <div class="fld"><label>Icône</label><div class="icon-pick" id="dv-icons">${ICONS.map((i) => `<button type="button" data-icon="${i}" class="${i === d.icon ? "on" : ""}" title="${esc(ICON_LBL[i])}" aria-label="${esc(ICON_LBL[i])}">${icon(i)}</button>`).join("")}</div></div>
    <div class="fld"><label for="dv-cat">Famille</label><select id="dv-cat">${CATS.map((c) => `<option ${c === d.cat ? "selected" : ""}>${esc(c)}</option>`).join("")}</select></div>
    <div class="fld"><label for="dv-conn">Type de liaison</label><select id="dv-conn"><option value="">Automatique (${esc(LINK[lk.type] || "?")})</option><option value="wired">Ethernet (forcé)</option><option value="wifi">Wi-Fi (forcé)</option></select></div>
    <div class="fld"><label for="dv-note">Note</label><textarea id="dv-note" maxlength="300" placeholder="Emplacement, propriétaire, usage…">${esc(d.note || "")}</textarea></div>
    <label class="chk"><input type="checkbox" id="dv-trust" ${d.trusted ? "checked" : ""}> Appareil de confiance (reconnu, il ne remonte plus comme « à identifier »)</label>
    <div class="dr-actions"><button class="btn primary" data-save>Enregistrer</button><button class="btn ghost" data-reset>Nom automatique</button><span class="dr-msg" id="dv-msg" role="status"></span></div>
    <h3>Liaison réseau</h3>
    <div class="link-big">${icon(lk.type === "wired" ? "cable" : lk.type === "wifi" ? "wifi" : "unknown")}<div><b>${esc(LINK[lk.type] || "Indéterminée")}</b>${lk.speed_mbps ? ` · <b>${fmtMbps(lk.speed_mbps)}</b> négociés` : ""}<div class="cell-sub">source : ${esc(lk.source || "?")} · confiance ${esc(lk.confidence || "?")}</div></div></div>
    ${(lk.evidence || []).length ? `<ul class="ev-list">${lk.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : ""}
    <dl class="dd mt">
      <dt>Latence</dt><dd>${rtt.avg != null ? `${nf1.format(rtt.avg)} ms (min ${nf1.format(rtt.min)} · max ${nf1.format(rtt.max)})` : d.state === "LOCAL" ? "machine locale" : d.alive ? "ne répond pas au ping" : "–"}</dd>
      <dt>Gigue</dt><dd>${rtt.jitter != null ? nf1.format(rtt.jitter) + " ms" : "–"}${rtt.loss ? ` · perte ${nf0.format(rtt.loss)} %` : ""}</dd>
      <dt>Débit avec le NAS</dt><dd>${cl ? `${fmtRate(cl.rx + cl.tx)} <span class="cell-sub">(↓ ${fmtRate(cl.rx)} · ↑ ${fmtRate(cl.tx)})</span>` : "aucun échange en cours"}</dd>
      <dt>Débit NetScan</dt><dd>${d.ns_mbps ? nf1.format(d.ns_mbps) + " Mb/s" : "non mesuré"}${d.switch_port ? ` · port switch ${esc(d.switch_port)}` : ""}</dd>
    </dl>
    ${lk.type === "wifi" || lk.type === "unknown" ? '<div class="hint mt">Le débit de liaison Wi-Fi (PHY) et le signal ne sont connus que du routeur : InfraDash ne les invente pas.</div>' : ""}
    <h3>Réseau</h3>
    <dl class="dd"><dt>Adresse IP</dt><dd class="mono">${esc(d.ip || "—")}${d.ips && d.ips.length > 1 ? ` <span class="cell-sub">déjà vue : ${esc(d.ips.filter((x) => x !== d.ip).join(", "))}</span>` : ""}</dd>
      <dt>Adresse MAC</dt><dd class="mono">${esc(d.mac)}${d.random_mac ? ' <span class="tag mute" title="Bit « administré localement » : téléphones et montres changent d\'adresse par réseau Wi-Fi">aléatoire</span>' : ""}</dd>
      <dt>Fabricant</dt><dd>${esc(d.vendor || (d.random_mac ? "indéterminé (adresse privée)" : "inconnu"))}</dd>
      <dt>Nom DNS</dt><dd>${esc(d.hostname || "–")}</dd>
      <dt>NetScan</dt><dd>${d.in_ns ? `connu${d.ns_ip && d.ns_ip !== d.ip ? ` (en ${esc(d.ns_ip)})` : ""} · risque ${esc(d.risk)}${d.risk_score != null ? ` (${nf0.format(d.risk_score)})` : ""}` : "jamais vu"}</dd>
      <dt>Première vue</dt><dd>${d.first_seen ? fmtDate(d.first_seen) : "–"}</dd><dt>Dernière vue</dt><dd>${d.alive ? "maintenant" : d.last_seen ? fmtDate(d.last_seen) : "–"}</dd></dl>
    <h3>Services ouverts ${d.ports_t ? `<span class="cell-sub">sondage ${esc(ago(d.ports_t))}</span>` : ""}</h3>
    ${(d.ports || []).length ? `<div class="port-chips">${d.ports.map((p) => `<span class="chip ${p.risk ? "risk" : ""}" title="${esc(p.risk || "")}">${p.port}<small>${esc(p.service)}</small></span>`).join("")}</div>
      ${d.ports.filter((p) => p.risk).map((p) => `<div class="rem-warn">${esc(p.service)} : ${esc(p.risk)}</div>`).join("")}
      ${Object.entries(d.banners || {}).map(([p, b]) => `<div class="cell-sub mt">:${esc(p)} ${esc([b.ssh, b.server, b.title && "« " + b.title + " »"].filter(Boolean).join(" · "))}</div>`).join("")}`
      : `<div class="hint">${d.ports_t ? "Aucun des ports courants n'est ouvert." : "Pas encore sondé : lancez « Scanner le réseau » avec le sondage des ports."}</div>`}
    ${cves.length || (d.risk_factors || []).length ? `<h3>Sécurité</h3>${cves.map((g) => `<div class="rem-warn">${esc(g.product)} ${esc(g.version)} : ${g.n} CVE possibles (CVSS max ${nf1.format(g.max_cvss)})${g.why ? " — " + esc(g.why) : ""}</div>`).join("")}
      ${(d.risk_factors || []).length ? `<ul class="ev-list">${d.risk_factors.map((f) => `<li>${esc(f)}</li>`).join("")}</ul>` : ""}` : ""}`;
    $("#dv-conn").value = d.custom_conn || "";
    $("#drawer-back").hidden = false; dr.hidden = false;
    requestAnimationFrame(() => { $("#drawer-back").classList.add("on"); dr.classList.add("on"); });
  }
  async function saveDevice(reset) {
    const mac = LU.sel; if (!mac) return;
    const msg = $("#dv-msg");
    const body = { mac, name: reset ? "" : $("#dv-name").value, icon: LU.icon, cat: $("#dv-cat").value, note: $("#dv-note").value, trusted: $("#dv-trust").checked, conn: $("#dv-conn").value };
    toast(msg, "Enregistrement…");
    try {
      const r = await postJSON("/api/lan/device", body);
      if (!r.ok) return toast(msg, r.error || "Refusé", true);
      if (r.device) { const l = (S.slow.lan_inventory || {}).devices || []; const i = l.findIndex((x) => x.mac === mac); if (i >= 0) l[i] = r.device; }
      renderLan2(); openDevice(mac); toast($("#dv-msg"), "Enregistré ✓");
    } catch (e) { toast(msg, "Échec de l'enregistrement", true); }
  }
  function onDrawerClick(e) {
    if (e.target.closest("[data-close]")) return closeDevice();
    const ic = e.target.closest("[data-icon]");
    if (ic) { LU.icon = ic.dataset.icon; $$("#dv-icons button").forEach((b) => b.classList.toggle("on", b === ic)); return; }
    if (e.target.closest("[data-save]")) saveDevice(false);
    if (e.target.closest("[data-reset]")) saveDevice(true);
  }

  /* ============================================================ PORTS */
  const PT = { host: "nas", f: "all", q: "", data: null, t: 0, busy: false };
  const BIND = { all: ["info", "toutes interfaces"], lan: ["info", "LAN"], local: ["ok", "local seulement"], tailscale: ["mute", "Tailscale"], docker: ["mute", "réseau Docker"], other: ["mute", "autre"] };
  async function loadPorts() {
    if (PT.busy) return; PT.busy = true;
    try { PT.data = await get("/api/ports"); PT.t = now(); if (CURRENT === "ports") drawPorts(); } catch (e) { /* réessai au prochain rendu */ }
    PT.busy = false;
  }
  function ptFilter(list) {
    const q = PT.q.trim().toLowerCase();
    const f = { all: () => true, docker: (e) => e.kind === "docker", sys: (e) => e.kind !== "docker", reserved: (e) => e.state === "réservé",
      lan: (e) => e.state === "écoute" && (e.bind === "all" || e.bind === "lan"), net: (e) => (e.domains || []).length > 0, db: (e) => e.db }[PT.f];
    return list.filter(f).filter((e) => !q || [e.port, e.proto, e.service, e.owner, e.process, e.kind].some((x) => String(x || "").toLowerCase().includes(q)));
  }
  function drawPorts() {
    const h = ((PT.data || {}).hosts || {})[PT.host];
    if (!h) { setHTML($("#pt-kpis"), ""); setHTML($("#pt-table"), '<tr><td class="empty">Relevé en cours (premier passage dans ~20 s)…</td></tr>'); return; }
    if (h.ok === false && !(h.ports || []).length) { setHTML($("#pt-table"), `<tr><td class="empty">${esc(h.error || "Machine injoignable")}</td></tr>`); return; }
    const ports = h.ports || [], live = ports.filter((e) => e.state === "écoute"), res = ports.filter((e) => e.state === "réservé");
    const lanExp = live.filter((e) => e.proto === "tcp" && (e.bind === "all" || e.bind === "lan") && e.kind !== "système");
    const dbs = live.filter((e) => e.db && e.bind === "all" && e.proto === "tcp");
    $("#pt-src").textContent = `${h.source || ""} · relevé ${ago(h.t)}${h.error ? " · dernier essai en erreur : " + h.error : ""}`;
    setHTML($("#pt-kpis"), [
      ["En écoute", nf0.format(new Set(live.map((e) => e.port + e.proto)).size), `${live.filter((e) => e.kind === "docker").length} par des conteneurs`, "var(--blue)"],
      ["Réservés", nf0.format(res.length), `par ${h.n_stopped || 0} conteneur(s) arrêté(s)`, res.length ? "var(--amber)" : "var(--ok)"],
      ["Conflits", nf0.format((h.conflicts || []).length), "ports réservés déjà pris", (h.conflicts || []).length ? "var(--crit)" : "var(--ok)"],
      ["Bases sur le LAN", nf0.format(dbs.length), "ports de bases ouverts à tout le réseau", dbs.length ? "var(--warn)" : "var(--ok)"],
      ["Ports libres", nf0.format((h.free || {}).n_free || 0), `entre 1024 et ${((h.free || {}).ephemeral || [32768])[0] - 1} (hors éphémères)`, "var(--green)"],
    ].map(([l, v, f, a]) => `<div class="card kpi" style="--accent:${a}"><div class="lbl">${l}</div><div class="val">${v}</div><div class="foot">${f}</div></div>`).join(""));
    setHTML($("#pt-conf"), (h.conflicts || []).length ? `<div class="pt-conf">${h.conflicts.map((c) => `<div class="pt-al ${c.level === "crit" ? "" : "warn"}"><b>Port ${c.port}/${esc(c.proto)}</b> — ${esc(c.text)}</div>`).join("")}</div>` : "");
    const list = ptFilter(ports).slice(0, 500);
    $("#pt-count").textContent = `${list.length} / ${ports.length}`;
    setHTML($("#pt-table"), `<tr><th>Port</th><th>Interface</th><th>Service</th><th>Conteneur / processus</th><th>Exposition</th></tr>` + (list.map((e) => {
      const b = BIND[e.bind] || BIND.other;
      return `<tr class="${e.state === "réservé" ? "res" : ""}"><td><b class="mono">${e.port}</b> <span class="tag mute">${esc(e.proto)}</span>${e.state === "réservé" ? ' <span class="tag warn" title="Conteneur arrêté : le port reste réservé à son redémarrage">réservé</span>' : ""}</td>
        <td><span class="tag ${b[0]}">${esc(b[1])}</span></td><td>${esc(e.service || "—")}${e.db ? ' <span class="tag warn">base</span>' : ""}</td>
        <td>${esc(e.owner || e.process || "—")}<div class="cell-sub">${esc(e.kind)}${e.stopped ? " · " + esc(e.stopped) : ""}</div></td>
        <td>${(e.domains || []).length ? `<span class="tag crit">Internet</span> <span class="cell-sub">${esc(e.domains.slice(0, 2).join(", "))}${e.domains.length > 2 ? "…" : ""}</span>` : e.bind === "local" ? '<span class="cell-sub">interne</span>' : '<span class="cell-sub">LAN</span>'}</td></tr>`;
    }).join("") || '<tr><td colspan="5" class="empty">Aucun port pour ce filtre</td></tr>'));
    const fr = h.free || {};
    $("#pt-free-sub").textContent = fr.ephemeral ? `éphémères ${fr.ephemeral[0]}–${fr.ephemeral[1]} exclus` : "";
    setHTML($("#pt-free"), (fr.bands || []).map((b) => `<div class="band"><div class="row-flex"><b>${esc(b.label)}</b><span>${nf0.format(b.free)} libres / ${nf0.format(b.total)}</span></div>
      <div class="bar"><i style="width:${Math.round((100 * b.free) / b.total)}%"></i></div>
      <div class="port-chips mt">${(b.sample || []).slice(0, 10).map((p) => `<button class="chip" data-port="${p}" title="Copier">${p}</button>`).join("") || '<span class="cell-sub">aucun</span>'}</div></div>`).join("")
      + `<div class="cell-sub">Plages libres : ${(fr.ranges || []).slice(0, 14).map((r) => (r[0] === r[1] ? r[0] : r[0] + "–" + r[1])).join(", ")}${(fr.n_ranges || 0) > 14 ? "…" : ""}</div>`);
    const lan = inv().filter((d) => d.alive && (d.ports || []).length).slice(0, 14);
    setHTML($("#pt-lan"), lan.length ? lan.map((d) => `<div class="ns-dev"><span class="dot ${(d.ports || []).some((p) => p.risk) ? "crit" : "ok"}"></span><div><b>${esc(d.name)}</b> <span class="cell-sub mono">${esc(d.ip)}</span>
      <div class="port-chips mt">${d.ports.map((p) => `<span class="chip ${p.risk ? "risk" : ""}">${p.port}<small>${esc(p.service)}</small></span>`).join("")}</div></div></div>`).join("") : '<div class="hint">Aucun port sondé : « Scanner le réseau » avec le sondage des ports.</div>');
  }
  function renderPorts() {
    if (!$("#pt-host").dataset.init) {
      $("#pt-host").dataset.init = 1;
      $("#pt-host").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { $$("#pt-host button").forEach((x) => x.classList.toggle("on", x === b)); PT.host = b.dataset.h; drawPorts(); } });
      $("#pt-filter").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { $$("#pt-filter button").forEach((x) => x.classList.toggle("on", x === b)); PT.f = b.dataset.f; drawPorts(); } });
      $("#pt-search").addEventListener("input", (e) => { PT.q = e.target.value; drawPorts(); });
      $("#v-ports").addEventListener("click", (e) => { const c = e.target.closest("[data-port]"); if (c) { navigator.clipboard && navigator.clipboard.writeText(c.dataset.port); c.classList.add("copied"); } });
      $("#pt-go").addEventListener("click", async () => {
        const lo = +$("#pt-from").value || 1, hi = +$("#pt-to").value || lo + 99;
        const r = await get(`/api/ports/free?host=${PT.host}&from=${lo}&to=${hi}&n=60`);
        setHTML($("#pt-found"), r.error ? `<div class="hint">${esc(r.error)}</div>` : `<div class="cell-sub">${r.ports.length} port(s) libre(s) entre ${r.from} et ${r.to} sur ${esc(PT.host)} :</div><div class="port-chips mt">${r.ports.map((p) => `<button class="chip" data-port="${p}">${p}</button>`).join("") || "aucun"}</div>`);
      });
    }
    if (!PT.data || now() - PT.t > 15) loadPorts();
    if (PT.data) drawPorts();
  }
  RENDER.ports = renderPorts;

  /* ============================================================ ARCHITECTE */
  const DOM = { reseau: "Réseau", securite: "Sécurité", stockage: "Stockage", sauvegarde: "Sauvegarde", conteneurs: "Conteneurs", supervision: "Supervision", performance: "Performance" };
  function renderArchitect() {
    if (!$("#ar-run").dataset.init) {
      $("#ar-run").dataset.init = 1;
      $("#ar-run").addEventListener("click", async () => {
        const b = $("#ar-run"); b.disabled = true;
        try { const r = await postJSON("/api/architect/run", {}); $("#ar-status").innerHTML = `<div class="hint">${esc(r.message || "")}</div>`; if (r.accepted) { S.derived.architect = Object.assign({}, D().architect, { status: "en_cours", phase: "demarrage" }); pollArch(); } } catch (e) { $("#ar-status").innerHTML = '<div class="hint">Échec de la demande.</div>'; }
        b.disabled = false;
      });
    }
    const a = D().architect || { facts: [] }, fs = a.facts || [], busy = a.status === "en_cours";
    $("#ar-run").disabled = busy; $("#ar-run").innerHTML = busy ? '<span class="ai-spin"></span> Analyse en cours…' : `${icon("ai")}Analyser l'architecture`;
    $("#ar-model").textContent = a.model ? "· " + a.model : "";
    const PH = { demarrage: "démarrage", contexte: "préparation des constats", controle_gpu: "contrôle du GPU", chargement: "chargement du modèle", generation: "rédaction du plan" };
    setHTML($("#ar-status"), busy ? `<div class="hint"><span class="ai-spin"></span> ${esc(PH[a.phase] || a.phase || "")} — 40 à 120 s sur le GPU du NAS</div>`
      : a.error ? `<div class="hint" style="color:var(--${a.status === "erreur" ? "crit" : "warn"})">${esc(a.error)}</div>`
      : a.result_t ? `<div class="hint">Dernière analyse ${esc(ago(a.result_t))}${a.duration_s ? " en " + nf0.format(a.duration_s) + " s" : ""}. Les constats ci-contre sont recalculés toutes les 2 minutes.</div>` : '<div class="hint">Aucune analyse IA pour l\'instant : les constats vérifiables ci-contre sont déjà disponibles.</div>');
    const r = a.result;
    const idLabel = Object.fromEntries(fs.map((f) => [f.id, f.title]));
    setHTML($("#ar-result"), r ? `<div class="card"><div class="row-flex"><h2 style="margin:0">Diagnostic d'architecture</h2><span class="tag ${r.niveau === "solide" ? "ok" : r.niveau === "fragile" ? "crit" : "warn"}" style="margin-left:auto">${esc(r.niveau)}</span></div><p class="arch-sum mt">${esc(r.synthese)}</p></div>
      <div class="mt">${(r.recommandations || []).map((x) => `<div class="rec ${(x.priorite || "P2").toLowerCase()}"><div class="tags"><span class="tag ${x.priorite === "P1" ? "crit" : x.priorite === "P2" ? "warn" : "info"}">${esc(x.priorite)}</span><span class="tag">${esc(DOM[x.domaine] || x.domaine)}</span><span class="tag ok" title="Gain attendu">gain ${esc(x.gain)}</span><span class="tag mute">effort ${esc(x.effort)}</span><span class="tag ${x.risque === "aucun" || x.risque === "faible" ? "mute" : "warn"}" title="Risque du changement">risque ${esc(x.risque)}</span>${x.source === "dashboard" ? '<span class="tag mute" title="L\'IA avait omis ce constat : repris avec sa correction vérifiée">ajouté par le dashboard</span>' : ""}</div>
        <h3>${esc(x.titre)}</h3>${x.pourquoi ? `<p>${esc(x.pourquoi)}</p>` : ""}${x.etat_cible ? `<p class="target"><b>État cible :</b> ${esc(x.etat_cible)}</p>` : ""}
        <ol>${(x.etapes || []).map((e) => `<li>${esc(e)}</li>`).join("")}</ol>
        ${x.verification ? `<div class="meta"><b>Vérifier :</b> ${esc(x.verification)}</div>` : ""}${x.retour_arriere ? `<div class="meta"><b>Retour arrière :</b> ${esc(x.retour_arriere)}</div>` : ""}
        <div class="refs">${(x.faits || []).map((id) => `<span class="tag mute" title="${esc(idLabel[id] || (r.labels || {})[id] || "Constat du diagnostic général")}">${esc(id)}</span>`).join("")}</div></div>`).join("")}
        ${(r.ne_pas_faire || []).length ? `<div class="card"><h2>À ne pas faire ici</h2>${r.ne_pas_faire.map((t) => `<div class="nofaire">${esc(t)}</div>`).join("")}</div>` : ""}</div>`
      : '<div class="card"><div class="empty">Cliquez sur « Analyser l\'architecture » : l\'IA locale reçoit les constats ci-contre et rédige un plan priorisé (état cible, étapes, vérification, retour arrière).</div></div>');
    $("#ar-facts-sub").textContent = fs.length ? `${fs.length} constat(s)` : "";
    setHTML($("#ar-facts"), fs.map((f) => `<div class="fact"><span class="dot ${f.level === "crit" ? "crit" : f.level === "warn" ? "warn" : ""}"></span><div style="min-width:0"><b>${esc(f.title)}</b> <span class="id">${esc(f.id)}</span>
      <div class="cell-sub">${esc(HOST_LABEL[f.host] || f.host)} · ${esc(DOM[f.domain] || f.domain)}</div><div class="cell-sub">${esc(f.evidence)}</div>
      <details><summary>Comment corriger</summary><div class="cell-sub" style="color:var(--text2)">${esc(f.hint)}</div></details></div></div>`).join("") || '<div class="empty">Aucune incohérence détectée 🎉</div>');
  }
  async function pollArch() {
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2500));
      try { const st = await get("/api/state"); S.derived = st.derived || S.derived; } catch (e) { continue; }
      if (CURRENT === "architect") renderArchitect();
      if ((D().architect || {}).status !== "en_cours") break;
    }
  }
  RENDER.architect = renderArchitect;

  /* ============================================================ EXÉCUTION SÉCURISÉE DES CORRECTIONS */
  const REM = { cat: null, t: 0, busy: false, plan: null, run: null, timer: null };
  async function loadRemCatalog() {
    if (REM.busy || (REM.cat && now() - REM.t < 30)) return; REM.busy = true;
    try { REM.cat = await get("/api/remedy/catalog"); REM.t = now(); decorateRemedy(); } catch (e) { /* le plan reste copiable */ }
    REM.busy = false;
  }
  function decorateRemedy() {
    if (!REM.cat || CURRENT !== "vulns") return;
    const acts = Object.fromEntries((((SL().vulns || {}).actions) || []).map((a) => [a.id, a]));
    $$("#vu-plan .vuln-action").forEach((card) => {
      card.querySelectorAll(".rem-exec").forEach((n) => n.remove());
      const rc = card.querySelector("[data-recheck]"); if (!rc) return;
      const id = rc.dataset.recheck, a = acts[id], items = (REM.cat.actions || {})[id];
      if (!a || !items || !items.length) return;
      const cmds = a.commands || [];
      const box = document.createElement("div"); box.className = "rem-exec";
      box.innerHTML = items.map((it) => `<div class="rem-row"><span class="mono" title="${esc(cmds[it.index] || "")}">${esc(String(cmds[it.index] || "").replace(/\s+/g, " ").slice(0, 90))}</span>
        ${it.executable ? `<button class="btn small" data-rem-a="${esc(id)}" data-rem-i="${it.index}" title="${esc(it.steps.join(" → "))}">${icon("play")}Préparer l'exécution</button>`
          : `<span class="tag mute" title="${esc(it.reason || "")}">à copier</span>`}</div>
        ${!it.executable && it.reason ? `<div class="cell-sub" style="margin:-2px 0 2px 8px">${esc(it.reason)}</div>` : ""}`).join("");
      (card.querySelector(".vuln-cmd") || card.querySelector(".vuln-rem") || card.firstElementChild).after(box);
    });
    const rm = D().remedy;
    const top = $("#vu-refresh");
    if (top && rm && rm.status === "en_cours" && !$(".rem-back")) {
      let b = $("#rem-banner"); if (!b) { b = document.createElement("div"); b.id = "rem-banner"; b.className = "rem-banner"; top.before(b); }
      b.innerHTML = `<span class="ai-spin"></span> Correction en cours : ${esc(rm.title || "")} <button class="btn small" data-rem-open>Suivre</button>`;
    } else if ($("#rem-banner")) $("#rem-banner").remove();
  }
  const baseVulns = RENDER.vulns;
  RENDER.vulns = function (first) {
    baseVulns(first); loadRemCatalog(); decorateRemedy();
    const pl = $("#vu-plan");
    if (pl && !pl.dataset.obs) {   // le plan est réécrit par views.js (chargement asynchrone, mises à jour) : on remet les boutons
      pl.dataset.obs = 1;
      new MutationObserver(() => {
        const todo = $$(".vuln-action", pl).some((c) => { const rc = c.querySelector("[data-recheck]"); return rc && ((REM.cat || {}).actions || {})[rc.dataset.recheck] && !c.querySelector(".rem-exec"); });
        if (todo) decorateRemedy();
      }).observe(pl, { childList: true });
    }
  };
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-rem-a]");
    if (b) return openRem(b.dataset.remA, +b.dataset.remI);
    if (e.target.closest("[data-rem-open]")) return openRunView();
  });

  function closeRem() { clearInterval(REM.timer); REM.timer = null; const n = $(".rem-back"); if (n) n.remove(); }
  function remShell(inner) {
    let n = $(".rem-back");
    if (!n) { n = document.createElement("div"); n.className = "rem-back"; n.innerHTML = '<div class="rem-modal" role="dialog" aria-modal="true" aria-label="Exécution d\'une correction"></div>'; document.body.appendChild(n); n.addEventListener("mousedown", (e) => { if (e.target === n && !(REM.run && REM.run.status === "en_cours")) closeRem(); }); }
    n.firstChild.innerHTML = inner;
  }
  async function openRem(aid, idx) {
    remShell('<h2>Préparation…</h2><div class="hint"><span class="ai-spin"></span> Vérifications en lecture seule sur la machine (dossiers, services du compose, espace disque).</div>');
    let p;
    try { p = await postJSON("/api/remedy/plan", { action: aid, index: idx }); } catch (e) { return remShell('<h2>Échec</h2><div class="rem-err">Le serveur n\'a pas répondu.</div><div class="rem-foot"><button class="btn" data-x>Fermer</button></div>'); }
    REM.plan = p;
    if (!p.ok) {
      remShell(`<h2>${p.refused ? "Commande non exécutable ici" : "Impossible"}</h2><div class="rem-err">${esc(p.error)}</div>${p.command ? `<h3>Commande du plan</h3><code class="rem-cmd">${esc(p.command)}</code><div class="hint mt">Elle reste utilisable à la main : la grammaire de sécurité n'autorise que des opérations Docker Compose, sed -i.bak et tar bornées.</div>` : ""}<div class="rem-foot"><button class="btn" data-x>Fermer</button></div>`);
      return bindRem();
    }
    const cap = p.caps || {}, ok = p.preflight_ok;
    remShell(`<h2>${esc(p.title || "Correction")}</h2><div class="cell-sub">${esc(HOST_LABEL[p.host] || p.host)} · empreinte <span class="mono">${esc(p.fingerprint)}</span> · valable 10 min</div>
      <h3>Ce qui sera exécuté, dans l'ordre</h3><ol class="rem-steps">${p.steps.filter((s) => s.kind !== "cd").map((s, i) => `<li><span class="st">${i + 1}</span><span>${esc(s.text)}</span></li>`).join("")}</ol>
      ${p.impact ? `<div class="rem-warn">${esc(p.impact)}</div>` : ""}${(p.warnings || []).map((w) => `<div class="rem-warn">${esc(w)}</div>`).join("")}
      <h3>Vérifications préalables</h3>${p.checks.map((c) => `<div class="rem-chk"><span class="${c.level}">${c.ok ? "✓" : c.level === "warn" ? "!" : "✗"}</span><span>${esc(c.text)}</span></div>`).join("") || '<div class="hint">Aucune.</div>'}
      ${(p.rollback || []).length ? `<h3>Pour revenir en arrière</h3><ul class="ev-list">${p.rollback.map((r) => `<li class="mono" style="overflow-wrap:anywhere">${esc(r)}</li>`).join("")}</ul>` : ""}
      <h3>Commande du plan</h3><code class="rem-cmd">${esc(p.command)}</code>
      ${!cap.enabled ? `<div class="rem-warn">Exécution désactivée (${esc(cap.reason || "")}). Pour l'activer une fois, sur le homelab :<code class="rem-cmd">${esc(cap.setup)}</code>Elle définit une phrase secrète (stockée hachée) exigée à chaque exécution. Le plan ci-dessus reste copiable.</div>` : !ok ? '<div class="rem-err">Une vérification a échoué : corrigez-la puis préparez à nouveau.</div>'
        : `<div class="rem-pin"><input type="password" class="search" id="rem-pin" autocomplete="off" placeholder="Phrase secrète" aria-label="Phrase secrète"><button class="btn primary" data-go>Exécuter maintenant</button></div>`}
      <div class="rem-err" id="rem-err" role="alert"></div><div class="rem-foot"><button class="btn ghost" data-x>Fermer</button></div>`);
    bindRem();
  }
  function bindRem() {
    const m = $(".rem-modal"); if (!m) return;
    m.onclick = (e) => {
      if (e.target.closest("[data-x]")) closeRem();
      if (e.target.closest("[data-go]")) go();
    };
    const pin = $("#rem-pin"); if (pin) { pin.focus(); pin.onkeydown = (e) => { if (e.key === "Enter") go(); }; }
    async function go() {
      const v = $("#rem-pin").value; if (!v) return;
      $("#rem-err").textContent = "";
      let r;
      try { r = await postJSON("/api/remedy/run", { plan_id: REM.plan.plan_id, fingerprint: REM.plan.fingerprint, pin: v }); } catch (e) { return ($("#rem-err").textContent = "Le serveur n'a pas répondu."); }
      $("#rem-pin").value = "";
      if (!r.ok) return ($("#rem-err").textContent = r.error || "Refusé");
      REM.run = r.run; drawRun(); poll();
    }
  }
  function openRunView() { get("/api/remedy/status").then((s) => { REM.run = s.run; if (REM.run) { drawRun(); poll(); } }); }
  function poll() {
    clearInterval(REM.timer);
    REM.timer = setInterval(async () => {
      try { const s = await get("/api/remedy/status"); REM.run = s.run; drawRun(); if (!s.run || s.run.status !== "en_cours") { clearInterval(REM.timer); REM.timer = null; REM.t = 0; loadRemCatalog(); } } catch (e) { /* réessai */ }
    }, 1500);
  }
  function drawRun() {
    const r = REM.run; if (!r) return;
    const ST = { ok: "✓", erreur: "✗", en_cours: "…", attente: "·", "annulé": "–" };
    remShell(`<h2>${r.status === "en_cours" ? '<span class="ai-spin"></span> ' : ""}${esc(r.title || "Correction")}</h2>
      <div class="cell-sub">${esc(HOST_LABEL[r.host] || r.host)} · ${r.status === "en_cours" ? "en cours" : r.status === "ok" ? "terminée" : "interrompue"}${r.finished ? " en " + fmtDur(r.finished - r.started) : ""}</div>
      <ol class="rem-steps mt">${r.steps.filter((s) => s.kind !== "cd").map((s) => `<li class="${esc(s.status)}"><span class="st">${ST[s.status] || "·"}</span><div>${esc(s.text)}${s.dur != null ? ` <span class="cell-sub">${fmtDur(s.dur)}</span>` : ""}${s.out ? `<pre class="rem-out">${esc(s.out)}</pre>` : ""}</div></li>`).join("")}</ol>
      ${r.status === "ok" ? `<div class="rem-warn" style="border-color:rgba(48,209,88,.4);background:rgba(48,209,88,.08)">Terminé. ${r.recheck ? "La revérification des versions réellement installées est lancée : le bilan s'affiche en haut du plan." : "Cliquez sur « Revérifier » pour confirmer que la version a bien changé."}</div>`
        : r.status === "erreur" ? '<div class="rem-err">Arrêt à la première erreur : rien d\'autre n\'a été exécuté. Les copies .bak et sauvegardes restent en place (voir « Pour revenir en arrière »).</div>' : ""}
      <div class="rem-foot"><button class="btn ghost" data-x ${r.status === "en_cours" ? "" : ""}>${r.status === "en_cours" ? "Masquer (continue en arrière-plan)" : "Fermer"}</button></div>`);
    bindRem();
  }
})();
