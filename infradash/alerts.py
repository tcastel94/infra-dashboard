"""Centre d'alertes : consolidation dédupliquée, cycle de vie, acquittement, notification Unraid (opt-in).

Sources consolidées (une alerte = une clé stable par problème, même si plusieurs sources le signalent) :
  diagnostics crit/warn (derived.insights), vulnérabilités critique/haute (slow.vulns), prévisions crit
  (derived.forecasts), constats crit/warn des flux sortants (slow.egress), machines/DNS injoignables (live.*),
  sauvegardes en retard (derived.backups).
Cycle de vie : nouvelle -> (acquittée) -> résolue quand la condition disparaît (2 passages consécutifs, et
seulement si toutes ses sources ont répondu : une source absente ne résout rien ; une machine muette — NAS
injoignable, flux du NAS non relevés — ne résout rien non plus ; flux sortants : 10 min d'absence). Résolues gardées 7 jours.
Une alerte acquittée qui s'aggrave (attention -> critique) redevient non acquittée.

Notification : DÉSACTIVÉE PAR DÉFAUT. Si settings.notify_unraid est vrai, chaque nouvelle alerte critique (et
« attention » si settings.notify_warn) apparue après l'activation est transmise au système de notifications
Unraid (script officiel notify), qui la relaie vers les canaux configurés par l'utilisateur. Chaînes filtrées
par liste blanche de caractères + shlex.quote, 200 caractères max, 10 envois / 24 h, une fois par clé,
regroupement si rafale. Au plus une fois : un envoi incertain (timeout SSH, code ≠ 0) compte comme envoyé ; seul
un échec certain avant exécution (connexion impossible) est retenté. Jamais d'envoi depuis l'instance de test (INFRADASH_STAGING).
"""
import json
import os
import re
import shlex
import threading
import time

from .config import DATA_DIR
from .state import STATE

ALERTS_FILE = os.path.join(DATA_DIR, "alerts.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

KEEP_RESOLVED_S = 7 * 86400
RESOLVE_AFTER_MISSES = 2       # passages consécutifs sans la condition avant de résoudre
CONFIRM_DOWN_RUNS = 2          # une machine doit être vue injoignable 2 fois de suite
REOPEN_SILENT_S = 600          # réapparition < 10 min après résolution : rouverte sans nouvel événement
EGRESS_GRACE_S = 600           # flux sortants (instantané de 30 s) : résolus seulement après 10 min sans réapparition
LIVE_STALE_S = 120             # données live plus vieilles : machine considérée muette
MUTE_GRACE_S = 90              # après le retour d'une machine muette : le temps que diagnostics et flux soient recalculés
SAVE_EVERY_S = 300

NOTIFY_SCRIPT = "/usr/local/emhttp/webGui/scripts/notify"
NOTIFY_LINK = "http://192.168.2.4:7070/#insights"
NOTIFY_MAX_24H = 10
NOTIFY_BURST = 3               # au-delà de 3 alertes en attente : un seul envoi groupé
NOTIFY_MAX_AGE_S = 6 * 3600    # on n'envoie pas une alerte apparue il y a plus de 6 h (quota épuisé entre-temps)
NOTIFY_RETRY_S = 300
NOTIFY_SSH_TIMEOUT_S = 15
NOTIFY_MAXLEN = 200

LEVEL_RANK = {"info": 0, "warn": 1, "crit": 2}
DEFAULT_SETTINGS = {"notify_unraid": False, "notify_warn": False, "notify_since": None}
BOOL_SETTINGS = ("notify_unraid", "notify_warn")

_lock = threading.RLock()
_db = {"loaded": False, "active": {}, "resolved": [], "notified": {}, "sent": [], "last_sent": None, "last_error": None,
       "init": None}
_mem = {"saved_t": 0, "down_runs": {}, "sending": False, "next_try": 0, "dry_run": [], "mute_t": {}}
_NUM = re.compile(r"(?<![A-Za-z])\d[\d   .,]*")


# suffixe « (hôte + N conteneur(s)) » des titres DNS (brut ou normalisé « #conteneur ») : hors de la clé
_DNS_SUFFIX = re.compile(r"\s*\(hôte \+ [\d#]+\s*conteneurs?\)\s*$")


def _cut(s, n):
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n - 1].rstrip() + "…"


def _norm(s, n=80):
    return _NUM.sub("#", str(s or "").lower()).strip()[:n]


# =====================================================================================================
# Persistance
# =====================================================================================================
def _atomic_write(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"), default=str)
    os.replace(tmp, path)


def _load():
    if _db["loaded"]:
        return
    _db["loaded"] = True
    try:
        with open(ALERTS_FILE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return
    if isinstance(d, dict):
        for k in ("active", "notified"):
            if isinstance(d.get(k), dict):
                _db[k] = d[k]
        for k in ("resolved", "sent"):
            if isinstance(d.get(k), list):
                _db[k] = d[k]
        for k in ("last_sent", "last_error", "init"):
            _db[k] = d.get(k)
    # anciennes clés DNS dérivées du titre (« … (hôte + #conteneur) ») : ramenées sur la clé stable du groupe
    for tbl in (_db["active"], _db["notified"]):
        for k in [k for k in tbl if k.startswith("egress:dns:") and _DNS_SUFFIX.search(k)]:
            v, nk = tbl.pop(k), _DNS_SUFFIX.sub("", k)
            if nk not in tbl:
                tbl[nk] = dict(v, key=nk) if "key" in v else v


def _save():
    try:
        _atomic_write(ALERTS_FILE, {"v": 1, **{k: _db[k] for k in ("active", "resolved", "notified", "sent", "last_sent",
                                                                     "last_error", "init")}})
        _mem["saved_t"] = time.time()
    except OSError:
        pass


def get_settings():
    with _lock:
        st = dict(DEFAULT_SETTINGS)
        try:
            with open(SETTINGS_FILE) as f:
                d = json.load(f)
            if isinstance(d, dict):
                st.update(d)
        except (OSError, ValueError):
            pass
        for k in BOOL_SETTINGS:
            st[k] = bool(st.get(k))
        return st


def set_settings(d):
    """Met à jour les réglages connus (booléens) ; l'activation de la notification date le point de départ."""
    with _lock:
        cur = get_settings()
        new = dict(cur)
        for k in BOOL_SETTINGS:
            if k in (d or {}):
                new[k] = bool(d[k])
        if new["notify_unraid"] and not cur["notify_unraid"]:
            new["notify_since"] = time.time()   # seules les alertes apparues après l'activation seront envoyées
        try:
            _atomic_write(SETTINGS_FILE, new)
        except OSError:
            pass
        _publish(time.time(), new)
        return new


# =====================================================================================================
# Candidats (une entrée par problème, clé stable)
# =====================================================================================================
def _cand(key, level, title, detail, source, host, action=""):
    return {"key": key, "level": level, "title": _cut(title, 200), "detail": _cut(detail, 700), "source": source,
            "host": host or "infra", "action": _cut(action, 500)}


def _merge(cands, c):
    """Même clé signalée par plusieurs sources : niveau le plus grave, sources cumulées."""
    cur = cands.get(c["key"])
    if not cur:
        c["sources"] = [c["source"]]
        cands[c["key"]] = c
        return
    srcs = cur["sources"] + ([c["source"]] if c["source"] not in cur["sources"] else [])
    if LEVEL_RANK[c["level"]] > LEVEL_RANK[cur["level"]]:
        c = dict(c, action=c["action"] or cur["action"])
        cands[c["key"]] = c
    else:
        cur["action"] = cur["action"] or c["action"]
    cands[c["key"]]["sources"] = srcs
    cands[c["key"]]["source"] = " + ".join(srcs)


def _backup_ids():
    return [(ch.get("label", ""), ch.get("id")) for ch in (STATE.get("derived", "backups") or {}).get("chains") or []]


def insight_key(i, backups=None):
    """Clé canonique d'un diagnostic : partagée avec les autres sources quand elles parlent du même problème."""
    t, host = i.get("title", ""), i.get("host", "")
    rules = [
        (r"a changé d'IP", lambda m: f"ip-change:{host}"),
        (r"^Clé Tailscale de (\S+)", lambda m: f"tailscale-key:{m.group(1)}"),
        (r"^Tailscale de (\S+) hors ligne", lambda m: f"tailscale-key:{m.group(1)}"),
        (r"erreurs de parité dans le contrôle en cours", lambda m: "parity-errors-current"),
        (r"^Erreurs de parité récurrentes", lambda m: "parity-errors-recurrent"),
        (r"^Contrôle de parité en cours", lambda m: "parity-check-slow"),
        (r"^Aucune copie hors site", lambda m: "backup-offsite"),
        (r"^Cache NVMe", lambda m: "nas-cache-full"),
        (r"^Image Docker", lambda m: "nas-docker-img"),
        (r"^Certificat (\S+) expire", lambda m: f"cert:{m.group(1)}"),
        (r"bases de données exposées", lambda m: "db-exposed-lan"),
        (r"Nginx Proxy Manager orphelin", lambda m: "npm-orphans"),
        (r"domaine\(s\) public\(s\) en erreur", lambda m: "npm-broken"),
        (r"lien\(s\) morts", lambda m: "homepage-dead-links"),
        (r"^(\S+) : unhealthy", lambda m: f"container:{m.group(1)}:unhealthy"),
        (r"^(\S+) redémarre en boucle", lambda m: f"container:{m.group(1)}:restarting"),
        (r"^(\S+) arrêté \(code", lambda m: f"container:{m.group(1)}:exited"),
        (r"^(\S+) chaud :", lambda m: f"disk-temp:{m.group(1)}"),
        (r"^(\S+) : DISK_", lambda m: f"disk-status:{m.group(1)}"),
        (r"^(\S+) : \d+ erreurs de lecture", lambda m: f"disk-errors:{m.group(1)}"),
        (r"^Onduleur : ", lambda m: "ups-status"),
    ]
    for rx, fn in rules:
        m = re.search(rx, t)
        if m:
            return fn(m)
    if t.startswith("Sauvegarde "):
        for label, bid in backups if backups is not None else _backup_ids():
            if label and f"Sauvegarde {label}" in t:
                return f"backup:{bid}"
    return f"diag:{host}:{_norm(t)}"


_FC_KEYS = [(r"^ts\.(.+)$", "tailscale-key:{}"), (r"^cert\.(.+)$", "cert:{}"), (r"^backup\.(.+)$", "backup:{}"),
            (r"^nas\.cache$", "nas-cache-full"), (r"^nas\.dockerimg$", "nas-docker-img"), (r"^nas\.parity$", "parity-check-slow"),
            (r"^homelab\.rootfs$", "homelab-rootfs")]


def forecast_key(fid):
    for rx, fmt in _FC_KEYS:
        m = re.match(rx, fid or "")
        if m:
            return fmt.format(*m.groups())
    return f"fc:{fid}"


def _vuln_title(a):
    if a.get("kind") == "exposition" or not a.get("n_findings"):
        return a.get("title") or a.get("component") or a.get("id")
    comp, ver = a.get("component") or a.get("id"), str(a.get("version") or "")
    if a.get("kind") == "unraid-os" or ver in ("inconnue", "None") or ver in comp:
        ver = ""
    n = a["n_findings"]
    return (f"{comp}{' ' + ver if ver else ''} : {n} vulnérabilité{'s' if n > 1 else ''}, priorité {a.get('priority', '?')}"
            + (" (KEV)" if a.get("kev") else "") + (", exposé sur Internet" if a.get("exposure") == "internet" else ""))


def _collect(now):
    cands, avail = {}, set()
    # --- diagnostics
    ins = STATE.get("derived", "insights")
    if isinstance(ins, list):
        avail.add("diagnostic")
        bks = _backup_ids()
        for i in ins:
            if i.get("level") in ("crit", "warn"):
                _merge(cands, _cand(insight_key(i, bks), i["level"], i.get("title"), i.get("detail"), "diagnostic", i.get("host"),
                                    i.get("action")))
    # --- vulnérabilités
    v = STATE.get("slow", "vulns")
    if isinstance(v, dict) and isinstance(v.get("actions"), list):
        avail.add("vulnérabilités")
        for a in v["actions"]:
            prio, expo = a.get("priority"), a.get("exposure")
            if prio not in ("critique", "haute") and not a.get("kev"):
                continue
            crit = prio == "critique" or a.get("kev") or (prio == "haute" and expo == "internet" and (
                a.get("kind") == "exposition" or a.get("n_findings")))
            det = (f"Score max {a.get('max_score', '?')}/100, {a.get('n_findings', 0)} constat(s)"
                   + (", présent dans le catalogue CISA KEV (exploité activement)" if a.get("kev") else "")
                   + f". Exposition : {expo}" + (f" ({a['exposure_detail']})" if a.get("exposure_detail") else "") + ".")
            act = (a.get("title") or "") + (" — " + _cut(a.get("remediation"), 300) if a.get("remediation") else "")
            _merge(cands, _cand("vuln:" + str(a.get("id")), "crit" if crit else "warn", _vuln_title(a), det, "vulnérabilités",
                                a.get("host"), act))
    # --- prévisions
    fc = STATE.get("derived", "forecasts")
    if isinstance(fc, dict) and isinstance(fc.get("items"), list):
        # un calcul en échec (VictoriaMetrics arrêté…) fait disparaître ses prévisions : rien n'est résolu tant qu'il échoue
        if not [e for e in fc.get("errors") or [] if not str(e).startswith("historique")]:
            avail.add("prévision")
        for it in fc["items"]:
            if it.get("severity") != "crit":
                continue
            eta = it.get("eta_days")
            title = it.get("title", it.get("id")) + (f" : échéance dans {eta:.1f} j".replace(".", ",") if isinstance(eta, (int, float)) else "")
            _merge(cands, _cand(forecast_key(it.get("id")), "crit", title, it.get("detail"), "prévision", it.get("host"),
                                "Voir l'onglet Prévisions."))
    # --- flux sortants
    eg = STATE.get("slow", "egress")
    if isinstance(eg, dict) and isinstance(eg.get("findings"), list):
        avail.add("flux sortants")
        src_host = {}   # IP de destination -> machines sources (pour rattacher l'alerte à une machine)
        for d in eg.get("destinations") or []:
            src_host[d.get("ip")] = [s.get("host") for s in d.get("sources") or [] if s.get("host")]
        for f in eg["findings"]:
            if f.get("level") not in ("crit", "warn"):
                continue
            kind, t = f.get("kind", ""), f.get("title", "")
            who = t.split("→")[0].split(":", 1)[-1].strip()
            if kind == "iot":
                key = "egress:iot"
            elif kind == "new":
                key = "egress:new"
            elif kind == "risk" and f.get("refs"):
                key = f"egress:risk:{f['refs'][0]}"
            elif kind == "dns":   # clé du groupe (« NAS Unraid »), pas du titre qui varie avec les conteneurs vus
                key = f"egress:dns:{_norm(f.get('group') or _DNS_SUFFIX.sub('', who), 60)}"
            else:
                key = f"egress:{kind}:{_norm(who, 60)}"
            hosts = [h for ip in f.get("refs") or [] for h in src_host.get(ip, [])]
            host = max(set(hosts), key=hosts.count) if hosts else "internet"
            _merge(cands, _cand(key, f["level"], t, f.get("detail"), "flux sortants", host, f.get("action")))
    # --- sauvegardes
    bk = STATE.get("derived", "backups")
    if isinstance(bk, dict) and isinstance(bk.get("chains"), list):
        avail.add("sauvegardes")
        for ch in bk["chains"]:
            if ch.get("status") not in ("warn", "crit"):
                continue
            what = "absente" if not ch.get("last_time") else f"dernière il y a {float(ch.get('age_h') or 0):.0f} h"
            _merge(cands, _cand(f"backup:{ch.get('id')}", ch["status"], f"Sauvegarde {ch.get('label')} : {what}",
                                ch.get("problem") or f"Destination : {ch.get('dest', '?')}.", "sauvegardes", ch.get("from"),
                                "Activer le plugin Appdata Backup (déjà installé)." if ch.get("id") == "appdata" else ""))
    # --- supervision (machines, DNS), confirmée sur plusieurs passages
    hl, nas, cl, dns = (STATE.get("live", k) or {} for k in ("homelab", "nas", "clawhost", "dns"))
    if hl or nas:
        avail.add("supervision")
        checks = {
            "host-down:homelab": (bool(hl.get("down")), "homelab", "Homelab injoignable", hl.get("error", "")),
            "host-down:nas": (bool(nas.get("down")), "nas", "NAS injoignable (SSH)", nas.get("error", "")),
            "host-down:clawhost": (bool(cl) and cl.get("up") is False, "clawhost", "clawhost injoignable",
                                   f"Aucune sonde ne répond sur {cl.get('ip', '192.168.2.5')}."),
            "dns-down": (bool(dns) and dns.get("ok") is False, "homelab", "DNS du réseau (AdGuard) en panne",
                         "La résolution via AdGuard (127.0.0.1) échoue : tout le réseau perd Internet."),
        }
        runs = _mem["down_runs"]
        for key, (bad, host, title, det) in checks.items():
            runs[key] = runs.get(key, 0) + 1 if bad else 0
            if runs[key] >= CONFIRM_DOWN_RUNS:
                _merge(cands, _cand(key, "crit", title, det, "supervision", host,
                                    "Vérifier l'alimentation, le câble réseau et l'adresse IP de la machine."))
    # --- réseau local (NetScan) : seuls les constats de gravité élevée (NetScan alerte déjà lui-même sur Telegram)
    ns = STATE.get("slow", "netscan")
    if isinstance(ns, dict) and ns.get("ok"):
        avail.add("réseau local")
        for g in (ns.get("digest") or {}).get("active") or []:
            if g.get("precise") and g.get("max_cvss", 0) >= 9:
                _merge(cands, _cand(f"netscan:{g.get('mac') or g.get('ip')}:{g.get('product')}", "warn",
                                    f"{g['device']} : {g['product']} {g['version']} vulnérable (CVSS {g['max_cvss']})",
                                    f"{g['n']} CVE dont {', '.join(g['cves'][:3])} — appareil {g['ip']} présent sur le réseau.", "réseau local", None,
                                    f"Mettre à jour le logiciel de {g['device']}, ou l'isoler du LAN s'il ne reçoit plus de mises à jour."))
    return cands, avail


def _mute(now):
    """Sous-sources muettes : machine injoignable ou figée (live.*), flux du NAS non relevés (egress). Leurs constats
    disparaissent sans que les problèmes soient réglés : pas de résolution, ni pendant MUTE_GRACE_S après leur retour."""
    seen = _mem["mute_t"]
    for h in ("nas", "homelab"):
        lv = STATE.get("live", h) or {}
        if not lv or lv.get("down") or now - (lv.get("t") or now) > LIVE_STALE_S:
            seen[h] = now
    cov = (STATE.get("slow", "egress") or {}).get("coverage") or {}
    if (cov.get("nas") or {}).get("ok") is False:
        seen["egress"] = now
    return {k for k, t in seen.items() if now - t < MUTE_GRACE_S}


# =====================================================================================================
# Cycle de vie
# =====================================================================================================
def _event_new(a, kind="Nouvelle alerte"):
    STATE.event(a["level"], a.get("host", "infra"), f"{kind} : {a['title']}", _cut(a.get("detail"), 300), "alerte")


def run():
    """Point d'entrée du runner (toutes les 30 s) ; aussi appelé après un acquittement."""
    with _lock:
        _load()
        now = time.time()
        cands, avail = _collect(now)
        mute = _mute(now)
        active, resolved = _db["active"], _db["resolved"]
        bootstrap = not _db["init"]
        dirty = bootstrap
        fresh = []
        for k, c in cands.items():
            a = active.get(k)
            if a:
                worse = LEVEL_RANK[c["level"]] > LEVEL_RANK.get(a["level"], 1)
                if any(a.get(f) != c[f] for f in ("level", "title", "source")):
                    dirty = True
                a.update({f: c[f] for f in ("level", "title", "detail", "source", "sources", "host", "action")})
                a["last_seen"], a["miss"] = now, 0
                if worse:   # aggravation : redevient non acquittée, et notifiable au nouveau niveau
                    a.update({"acked": False, "ack_t": None, "escalated_t": now})
                    fresh.append((a, "Alerte aggravée"))
                continue
            prev = next((r for r in resolved if r.get("key") == k), None)
            a = dict(c, first_seen=now, last_seen=now, acked=False, ack_t=None, escalated_t=None, miss=0)
            if prev and now - (prev.get("resolved_t") or 0) < REOPEN_SILENT_S:
                a.update(first_seen=prev.get("first_seen", now), acked=prev.get("acked", False), ack_t=prev.get("ack_t"))
            elif not bootstrap:
                fresh.append((a, "Nouvelle alerte"))
            _db["resolved"] = resolved = [r for r in resolved if r.get("key") != k]
            active[k] = a
            dirty = True
        for k in [k for k in active if k not in cands]:
            a = active[k]
            if not all(s in avail for s in a.get("sources") or [a.get("source")]):
                continue   # source muette (démarrage, collecteur en panne) : on ne conclut rien
            if a.get("host") in mute or (k.startswith("egress:") and "egress" in mute):
                a["miss"] = 0
                continue   # machine muette (NAS injoignable…) : ses diagnostics et flux ont disparu, pas ses problèmes
            a["miss"] = a.get("miss", 0) + 1
            if a["miss"] >= RESOLVE_AFTER_MISSES and (not k.startswith("egress:")
                                                      or now - (a.get("last_seen") or 0) >= EGRESS_GRACE_S):
                del active[k]
                a.pop("miss", None)
                a["resolved_t"] = now
                resolved.append(a)
                dirty = True
                STATE.event("ok", a.get("host", "infra"), f"Alerte résolue : {a['title']}", "", "alerte")
        _db["resolved"] = [r for r in resolved if now - (r.get("resolved_t") or 0) < KEEP_RESOLVED_S][-300:]
        _db["notified"] = {k: v for k, v in _db["notified"].items() if k in active or now - (v.get("t") or 0) < KEEP_RESOLVED_S}
        _db["sent"] = [t for t in _db["sent"] if now - t < 86400]
        if bootstrap:
            _db["init"] = now
            ncrit = sum(1 for a in active.values() if a["level"] == "crit")
            STATE.event("info", "infra", f"Centre d'alertes activé : {len(active)} alerte(s) active(s), dont {ncrit} critique(s)",
                        "Les problèmes déjà présents sont repris sans notification.", "alerte")
        for a, kind in fresh:
            _event_new(a, kind)
        settings = get_settings()
        if settings["notify_unraid"]:
            _notify(now, settings)
        if dirty or now - _mem["saved_t"] >= SAVE_EVERY_S:
            _save()
        return _publish(now, settings)


def _public(a):
    return {k: a.get(k) for k in ("key", "level", "title", "detail", "source", "sources", "host", "first_seen", "last_seen",
                                  "acked", "ack_t", "action", "escalated_t", "resolved_t") if k in a}


def _publish(now, settings=None):
    _load()
    settings = settings or get_settings()
    act = sorted(_db["active"].values(), key=lambda a: (bool(a.get("acked")), -LEVEL_RANK.get(a["level"], 0), -a["first_seen"]))
    res = sorted(_db["resolved"], key=lambda r: -(r.get("resolved_t") or 0))[:20]
    sent24 = [t for t in _db["sent"] if now - t < 86400]
    out = {
        "active": [_public(a) for a in act], "resolved": [_public(r) for r in res],
        "counts": {"crit": sum(1 for a in act if a["level"] == "crit"), "warn": sum(1 for a in act if a["level"] == "warn"),
                   "new": sum(1 for a in act if not a.get("acked")), "acked": sum(1 for a in act if a.get("acked")),
                   "total": len(act)},
        "notify": {"enabled": settings["notify_unraid"], "notify_warn": settings["notify_warn"], "channel": "unraid",
                   "since": settings.get("notify_since"), "last_sent": _db["last_sent"], "sent_24h": len(sent24),
                   "max_24h": NOTIFY_MAX_24H, "pending": len(_pending(now, settings)) if settings["notify_unraid"] else 0,
                   "last_error": _db["last_error"],
                   "blocked": "instance de test : aucun envoi" if os.environ.get("INFRADASH_STAGING") else None},
        "t": now,
    }
    STATE.set("derived", "alerts", out)
    return out


def ack(key):
    with _lock:
        _load()
        a = _db["active"].get(key)
        if not a:
            return False
        a["acked"], a["ack_t"] = True, time.time()
        _save()
        _publish(time.time())
        return True


def unack(key):
    with _lock:
        _load()
        a = _db["active"].get(key)
        if not a:
            return False
        a["acked"], a["ack_t"] = False, None
        _save()
        _publish(time.time())
        return True


def ack_all(level=None):
    with _lock:
        _load()
        now, n = time.time(), 0
        for a in _db["active"].values():
            if not a.get("acked") and (level is None or a["level"] == level):
                a["acked"], a["ack_t"] = True, now
                n += 1
        _save()
        _publish(now)
        return n


# =====================================================================================================
# Notification Unraid (opt-in)
# =====================================================================================================
_SUBST = [("→", " vers "), ("'", "’"), ("`", "’"), ("«", ""), ("»", ""), ("—", "-"), ("–", "-"), ("…", "..."), ("·", "-"),
          ("×", "x"), ("≥", " au moins "), ("≤", " au plus ")]
_UNSAFE = re.compile(r"[^0-9A-Za-zÀ-ÖØ-öø-ÿŒœ .,:/%°+=@_’\-]")


def safe_text(s, n=NOTIFY_MAXLEN):
    """Liste blanche stricte (lettres, chiffres, espace et . , : / % ° + = @ _ ’ -), pas de tiret initial, n car. max."""
    s = str(s or "")
    for a, b in _SUBST:
        s = s.replace(a, b)
    s = _UNSAFE.sub(" ", s)
    s = " ".join(s.split()).lstrip("-+ ")
    if len(s) > n:
        s = s[:n - 3].rstrip() + "..."
    return s or "InfraDash"


def build_notify_cmd(subject, detail, level):
    """Commande exécutée sur le NAS (une seule écriture autorisée) ; chaque argument filtré puis quoté."""
    imp = "alert" if level == "crit" else "warning"
    args = [NOTIFY_SCRIPT, "-e", "InfraDash", "-s", safe_text(subject), "-d", safe_text(detail), "-i", imp, "-l", NOTIFY_LINK]
    return " ".join(shlex.quote(a) for a in args) + " >/dev/null 2>&1; echo rc=$?"


def _pending(now, settings):
    since = settings.get("notify_since") or now
    out = []
    for a in _db["active"].values():
        lvl = a["level"]
        if a.get("acked") or not (lvl == "crit" or (lvl == "warn" and settings["notify_warn"])):
            continue
        born = a.get("escalated_t") or a["first_seen"]
        n = _db["notified"].get(a["key"])
        if born < since or now - born > NOTIFY_MAX_AGE_S or (n and LEVEL_RANK.get(n.get("level"), 0) >= LEVEL_RANK[lvl]):
            continue
        out.append(a)
    out.sort(key=lambda a: (-LEVEL_RANK[a["level"]], a["first_seen"]))
    return out


def _messages(pending, room):
    """Une notification par alerte, ou une seule groupée en cas de rafale / quota serré."""
    host = {"nas": "NAS", "homelab": "Homelab", "clawhost": "clawhost", "internet": "Internet", "tailscale": "Tailscale"}
    if len(pending) > NOTIFY_BURST or len(pending) > room:
        nc = sum(1 for a in pending if a["level"] == "crit")
        subj = f"{len(pending)} nouvelles alertes" + (f" dont {nc} critiques" if nc else "")
        det = " / ".join(a["title"] for a in pending)
        return [(subj, det, "crit" if nc else "warn", [a for a in pending])]
    return [(("Critique : " if a["level"] == "crit" else "Attention : ") + a["title"],
             host.get(a.get("host"), a.get("host") or "Infra") + (" - " + (a.get("detail") or a.get("action"))
                                                                   if a.get("detail") or a.get("action") else ""), a["level"], [a])
            for a in pending]


def _ssh_send(cmd):
    """Exécution sur le NAS via la connexion SSH persistante du collecteur. Renvoie (ok, erreur, exécuté).
    « exécuté » n'est faux que pour un échec certain avant exécution (connexion impossible, ssh rc 255) : un timeout
    tue le client ssh local, pas le script distant, qui a donc pu notifier."""
    from . import nas   # import tardif : pas de connexion SSH au chargement du module
    t0 = time.monotonic()
    out = nas.SSHC.run(cmd, timeout=NOTIFY_SSH_TIMEOUT_S)
    if out is None:
        # timeout reconnu à la durée écoulée (last_error est partagé avec les collecteurs, qui peuvent l'écraser)
        if time.monotonic() - t0 >= NOTIFY_SSH_TIMEOUT_S - 1:
            return False, "SSH : timeout (envoi incertain, compté comme envoyé)", True
        return False, f"SSH : {nas.SSHC.last_error or 'échec'}", False
    m = re.search(r"rc=(\d+)", out)
    if not m or m.group(1) != "0":
        return False, f"script notify : code {m.group(1) if m else '?'} (compté comme envoyé)", True
    return True, None, True


def _notify(now, settings):
    if os.environ.get("INFRADASH_STAGING") or _mem["sending"] or now < _mem["next_try"]:
        return
    pend = _pending(now, settings)
    room = NOTIFY_MAX_24H - len([t for t in _db["sent"] if now - t < 86400])
    if not pend or room <= 0:
        return
    msgs = _messages(pend, room)[:room]
    _mem["sending"] = True

    def worker():
        try:
            for subj, det, lvl, alerts_ in msgs:
                if not get_settings()["notify_unraid"]:   # désactivé entre-temps
                    break
                ok, err, ran = _ssh_send(build_notify_cmd(subj, det, lvl))
                with _lock:
                    t = time.time()
                    if not ok:
                        _db["last_error"] = err
                        _mem["next_try"] = t + NOTIFY_RETRY_S
                        if ran:   # le script a pu notifier : compté dans le quota et jamais renvoyé (au plus une fois)
                            _db["sent"].append(t)
                            for a in alerts_:
                                _db["notified"][a["key"]] = {"level": a["level"], "t": t}
                        break
                    _db["sent"].append(t)
                    _db["last_sent"], _db["last_error"] = t, None
                    for a in alerts_:
                        _db["notified"][a["key"]] = {"level": a["level"], "t": t}
            with _lock:
                _save()
                _publish(time.time())
        finally:
            _mem["sending"] = False

    threading.Thread(target=worker, name="alerts.notify", daemon=True).start()
