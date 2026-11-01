"""Vues dérivées : planning unifié des tâches, état des sauvegardes, topologie des flux, diagnostics."""
import re
import time
from datetime import datetime, timedelta

from .config import BACKUP_CHAINS, HOSTS, KNOWN_IPS, PORT_PROTO, describe
from .state import STATE
from .util import TZ, Cron, cron_human, is_private, is_tailscale, redact


# --------------------------------------------------------------------------- crons
def _oncalendar_to_cron(cal):
    m = re.match(r"^\*-\*-\* (\d{1,2}):(\d{2})(?::\d{2})?$", cal.strip())
    if m:
        return f"{int(m.group(2))} {int(m.group(1))} * * *"
    m = re.match(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\*-\*-\* (\d{1,2}):(\d{2})", cal.strip())
    if m:
        d = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].index(m.group(1))
        return f"{int(m.group(3))} {int(m.group(2))} * * {d}"
    return {"daily": "0 0 * * *", "weekly": "0 0 * * 1", "monthly": "0 0 1 * *", "hourly": "0 * * * *"}.get(cal.strip())


_FREQ = {"hourly": "47 * * * *", "daily": "40 4 * * *", "weekly": "30 4 * * 0", "monthly": "20 4 1 * *"}


def build_jobs():
    now = datetime.now(TZ)
    jobs = []

    def add(host, schedule, command, source, user="root", title=None, desc=None, cat=None, enabled=True,
            last=None, nxt=None, note="", verified=True):
        t, d, c = describe(command)
        j = {"host": host, "schedule": schedule, "command": redact(command), "source": source, "user": user,
             "title": title or t, "desc": desc if desc is not None else d, "cat": cat or c, "enabled": enabled,
             "note": note, "verified": verified}
        try:
            if schedule and schedule != "@reboot" and enabled:
                cr = Cron(schedule)
                j["human"] = cron_human(schedule)
                j["next"] = (nxt or cr.next_run(now).timestamp())
                j["prev"] = last or (cr.prev_run(now).timestamp() if cr.prev_run(now) else None)
                j["per_day"] = round(cr.per_day(), 2)
                j["runs24"] = [r.timestamp() for r in cr.runs_between(now, now + timedelta(hours=24), limit=300)]
                j["runs7d_hours"] = sorted({r.hour for r in cr.runs_between(now, now + timedelta(days=7), limit=3000)})
            else:
                j["human"] = cron_human(schedule) if schedule else "désactivé"
                if nxt:
                    j["next"] = nxt
                if last:
                    j["prev"] = last
        except Exception:
            j["human"] = schedule
        j["id"] = f"{host}:{abs(hash((schedule, command))) % 10**8}"
        jobs.append(j)
        return j

    # Homelab
    hl = STATE.get("slow", "homelab") or {}
    for c in hl.get("crons", []):
        if "run-parts" in c["command"] and "cron.hourly" in c["command"] and not hl.get("run_parts", {}).get("hourly"):
            continue
        if "test -x /usr/sbin/anacron" in c["command"] or "/run/systemd/system" in c["command"]:
            continue  # inactif sous systemd (géré par un timer)
        add("homelab", c["schedule"], c["command"], c.get("source", ""), c.get("user", "root"), note=c.get("note", ""),
            verified=c.get("source") != "crontab root")
    for t in hl.get("timers", []):
        unit = t["unit"] or ""
        title, desc, cat = describe(unit)
        add("homelab", None, unit, "timer systemd", "root", title=title, desc=desc, cat=cat,
            last=t.get("last"), nxt=t.get("next"))
        jobs[-1]["human"] = "timer systemd"
        if t.get("next"):
            nx = t["next"]
            jobs[-1]["runs24"] = [nx] if nx - time.time() < 86400 else []
    rp = hl.get("run_parts", {})
    if rp.get("daily"):
        add("homelab", None, "anacron cron.daily: " + " ".join(rp["daily"]), "anacron", title="cron.daily (anacron)",
            desc="Scripts quotidiens via anacron : " + ", ".join(rp["daily"]) + ".", cat="systeme")
        jobs[-1]["human"] = "1×/jour via anacron"
    # NAS
    ns = STATE.get("slow", "nas_sched") or {}
    for c in ns.get("crons", []):
        cmd = c["command"]
        m = re.search(r"/scripts/([^/]+)/script", cmd)
        title = f"User Script : {m.group(1)}" if m else None
        add("nas", c["schedule"], cmd, c["source"], title=title if title and not describe(cmd)[1] else None)
    for u in ns.get("user_scripts", []):
        f = u.get("frequency")
        if f in ("custom",):
            continue  # déjà présent via /etc/cron.d/root
        sched = _FREQ.get(f)
        title, desc, cat = describe(u["name"])
        add("nas", sched if sched else None, f"user script {u['name']}", "User Scripts", title=f"User Script : {u['name']}",
            desc=desc or u.get("desc") or "", cat=cat if cat != "autre" else "script", enabled=f not in ("disabled", None, ""))
        if f == "boot":
            jobs[-1]["human"] = "au démarrage de l'array"
        elif f in ("disabled", None, ""):
            jobs[-1]["human"] = "désactivé"
    # clawhost (depuis la sauvegarde /etc)
    ce = STATE.get("slow", "claw_etc") or {}
    for t in ce.get("timers", []):
        if t["unit"] in ("snapd.snap-repair.timer",):
            continue
        cr = _oncalendar_to_cron(t.get("calendar", ""))
        j = add("clawhost", cr, t.get("exec") or t["unit"], "timer systemd (sauvegarde /etc)", title=None,
                desc=None, note=f"OnCalendar={t.get('calendar')} · lu dans la sauvegarde {ce.get('from_backup', '').rstrip('/').split('/')[-1]}",
                verified=False)
        if t.get("desc") and not j["desc"]:
            j["desc"] = t["desc"]
    for c in ce.get("crons", []):
        if "test -x /usr/sbin/anacron" in c["command"] or "/run/systemd/system" in c["command"]:
            continue
        add("clawhost", c["schedule"], c["command"], c["source"] + " (sauvegarde)", c.get("user", "root"), verified=False)
    jobs.sort(key=lambda j: (j.get("next") or 9e12))
    # Créneaux chargés : tâches lourdes (I/O disque ou réseau) sur 24 h
    buckets = {}
    for j in jobs:
        if (j.get("per_day") or 0) > 30 or j["cat"] not in ("backup", "stockage", "media") and "Auto-update" not in j["title"]:
            continue
        for r in j.get("runs24", []):
            h = datetime.fromtimestamp(r, TZ).strftime("%H:00")
            buckets.setdefault(h, []).append(j["title"])
    peak = sorted(buckets.items(), key=lambda kv: -len(kv[1]))[:3]
    # Densité hebdomadaire (jour x heure) des exécutions, hors tâches quasi continues
    week = [[0] * 24 for _ in range(7)]
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    for j in jobs:
        if not j.get("schedule") or not j.get("enabled") or (j.get("per_day") or 0) > 30 or j["schedule"] == "@reboot":
            continue
        try:
            for r in Cron(j["schedule"]).runs_between(start, start + timedelta(days=7), limit=500):
                week[(r.isoweekday() - 1) % 7][r.hour] += 1
        except Exception:
            continue
    return {"jobs": jobs, "peak": peak, "week": week, "t": time.time()}


# --------------------------------------------------------------------------- sauvegardes
def build_backups():
    b = STATE.get("slow", "nas_backups") or {}
    now = time.time()
    chains = []
    ns = STATE.get("slow", "nas_sched") or {}
    us = {u["name"]: u for u in ns.get("user_scripts", [])}
    for ch in BACKUP_CHAINS:
        items = b.get(ch["nas_dir"], []) if ch["nas_dir"] != "homelab-netnode" else b.get("homelab-netnode", [])
        items = [i for i in items if not i["name"].endswith(".part")]
        c = dict(ch)
        c["count"] = len(items)
        c["total"] = sum(i["size"] for i in items)
        c["sizes"] = [[round(i["mtime"]), i["size"]] for i in items[-40:]]
        if items:
            last = items[-1]
            age = (now - last["mtime"]) / 3600
            c.update({"last_name": last["name"], "last_size": last["size"], "last_time": last["mtime"], "age_h": round(age, 1)})
            c["status"] = "ok" if age <= ch["max_age_h"] else ("warn" if age <= ch["max_age_h"] * 2 else "crit")
            if len(items) >= 3:
                avg = sum(i["size"] for i in items[-8:-1]) / max(1, len(items[-8:-1]))
                c["size_delta"] = round(100 * (last["size"] - avg) / avg, 1) if avg else 0
            if ch["id"] == "clawhost":
                c["last_files"] = last.get("files", [])
        else:
            c["status"] = "crit"
        if ch["id"] == "appdata":
            u = us.get("backup_appdata", {})
            c["enabled"] = u.get("frequency") not in ("disabled", None, "")
            if not items:
                c["status"] = "crit"
                c["problem"] = "Aucune sauvegarde des appdata : le User Script backup_appdata est désactivé et le dossier backups/appdata est vide."
        chains.append(c)
    rf = b.get("root_files") or {}
    legacy = {"duplicati_files": rf.get("count", 0), "duplicati_size": rf.get("size", 0), "newest": rf.get("newest")}
    return {"chains": chains, "legacy": legacy, "offsite": False, "t": now}


# --------------------------------------------------------------------------- topologie
def _proto_of(ports):
    for p, _ in sorted(ports.items(), key=lambda kv: -kv[1]):
        if p in PORT_PROTO:
            return PORT_PROTO[p]
    return "tcp"


def build_topology():
    live = lambda k: STATE.get("live", k) or {}
    hl, nas, claw = live("homelab"), live("nas"), live("clawhost")
    hp, np_ = live("homelab_peers"), live("nas_peers")
    ts = live("tailscale")
    ct = STATE.get("live", "nas_conntrack") or []
    ncont = STATE.get("live", "nas_containers") or []
    hcont = STATE.get("live", "homelab_containers") or []
    edges = []

    def edge(a, b, rate_ab, rate_ba, proto, label, kind="lan", estimated=False, conns=None, detail=None):
        edges.append({"id": f"{a}-{b}-{proto}", "from": a, "to": b, "ab": round(max(0, rate_ab)), "ba": round(max(0, rate_ba)),
                      "proto": proto, "label": label, "kind": kind, "estimated": estimated, "conns": conns, "detail": detail or []})

    hif = (hl.get("ifaces") or {}).get("enp0s25", {})
    edge("box", "homelab", hif.get("rx", 0), hif.get("tx", 0), "lan", "enp0s25 · 1 GbE", "uplink")
    nif = (nas.get("ifaces") or {}).get("eth0") or (nas.get("ifaces") or {}).get("br0") or {}
    edge("box", "nas", nif.get("rx", 0), nif.get("tx", 0), "lan", "eth0 · br0", "uplink")
    # clawhost : on ne voit que ce qui passe par le homelab et le NAS
    c_h = hp.get(HOSTS["clawhost"]["ip"], {})
    c_n = np_.get(HOSTS["clawhost"]["ip"], {})
    claw_m = claw.get("metrics") or {}
    if claw_m:
        cif = max((claw_m.get("ifaces") or {}).values(), key=lambda x: x["rx"] + x["tx"], default={"rx": 0, "tx": 0})
        edge("box", "clawhost", cif["rx"], cif["tx"], "lan", "uplink clawhost", "uplink")
    else:
        edge("box", "clawhost", c_h.get("out", 0) + c_n.get("out", 0), c_h.get("in", 0) + c_n.get("in", 0), "lan",
             "observé depuis homelab + NAS", "uplink", estimated=True)
    # homelab <-> NAS
    a, b = hp.get(HOSTS["nas"]["ip"], {}), np_.get(HOSTS["homelab"]["ip"], {})
    out_hn = max(a.get("out", 0), b.get("in", 0))
    in_hn = max(a.get("in", 0), b.get("out", 0))
    ports = dict(a.get("ports", {}))
    for k, v in b.get("ports", {}).items():
        ports[int(k)] = ports.get(int(k), 0) + v
    edge("homelab", "nas", out_hn, in_hn, _proto_of(ports), "SSH collecte · SMB sauvegardes · métriques", conns=a.get("conns", 0) or b.get("conns", 0),
         detail=[f"port {p} × {n}" for p, n in sorted(ports.items(), key=lambda kv: -kv[1])[:6]])
    # NAS <-> clawhost
    cflows = [f for f in ct if f["src"] == HOSTS["clawhost"]["ip"] or f["dst"] == HOSTS["clawhost"]["ip"]]
    ports_nc = {}
    for f in cflows:
        ports_nc[f["dport"]] = ports_nc.get(f["dport"], 0) + f["n"]
    for k, v in c_n.get("ports", {}).items():
        ports_nc[int(k)] = ports_nc.get(int(k), 0) + v
    edge("nas", "clawhost", c_n.get("out", 0), c_n.get("in", 0), _proto_of(ports_nc) if ports_nc else "smb",
         "SMB (backups, appdata, médias) · Nexus → gateway", conns=sum(f["n"] for f in cflows) or c_n.get("conns", 0),
         detail=[f"port {p} × {n}" for p, n in sorted(ports_nc.items(), key=lambda kv: -kv[1])[:6]])
    if c_h:
        edge("homelab", "clawhost", c_h.get("out", 0), c_h.get("in", 0), _proto_of(c_h.get("ports", {})), "sondes dashboard",
             conns=c_h.get("conns", 0))
    else:
        edge("homelab", "clawhost", 0, 0, "probe", "sondes santé (TCP/HTTP)", estimated=True)
    # Internet : estimation à partir des pairs publics + part publique du trafic des conteneurs du NAS
    pub_in = sum(v.get("in", 0) for ip, v in hp.items() if not is_private(ip) and not is_tailscale(ip))
    pub_out = sum(v.get("out", 0) for ip, v in hp.items() if not is_private(ip) and not is_tailscale(ip))
    pub_in += sum(v.get("in", 0) for ip, v in np_.items() if not is_private(ip) and not is_tailscale(ip))
    pub_out += sum(v.get("out", 0) for ip, v in np_.items() if not is_private(ip) and not is_tailscale(ip))
    ip2c = {}
    for c in ncont:
        for x in c.get("ips", []):
            if "=" in x and x.split("=")[1]:
                ip2c[x.split("=")[1]] = c["name"]
    cpub, ctot = {}, {}
    client_flows = {}
    for f in ct:
        cname = ip2c.get(f["rsrc"]) or ip2c.get(f["src"])
        peer = f["src"] if ip2c.get(f["rsrc"]) else f["dst"]
        if not cname:
            continue
        ctot[cname] = ctot.get(cname, 0) + f["n"]
        if not is_private(peer) and not is_tailscale(peer):
            cpub[cname] = cpub.get(cname, 0) + f["n"]
        elif peer.startswith("192.168.2.") and peer not in (HOSTS["nas"]["ip"], HOSTS["homelab"]["ip"], HOSTS["clawhost"]["ip"]):
            key = (peer, cname)
            client_flows[key] = client_flows.get(key, 0) + f["n"]
    vpn = 0
    for c in ncont:
        tot = ctot.get(c["name"], 0)
        share = (cpub.get(c["name"], 0) / tot) if tot else (1.0 if "vpn" in c["name"] else 0)
        pub_in += c.get("rx", 0) * share
        pub_out += c.get("tx", 0) * share
        if "vpn" in c["name"]:
            vpn += c.get("rx", 0) + c.get("tx", 0)
    unb = next((c for c in hcont if c["name"] == "unbound"), {})
    pub_in += unb.get("rx", 0)
    pub_out += unb.get("tx", 0)
    edge("internet", "box", pub_in, pub_out, "https", "WAN (estimé)", "wan", estimated=True)
    # Clients LAN -> services du NAS (débit réparti selon le nombre de flux)
    cmap = {c["name"]: c for c in ncont}
    per_client = {}
    for (peer, cname), n in client_flows.items():
        tot = ctot.get(cname, 1)
        c = cmap.get(cname, {})
        d = per_client.setdefault(peer, {"rx": 0, "tx": 0, "services": {}})
        d["rx"] += c.get("tx", 0) * n / tot
        d["tx"] += c.get("rx", 0) * n / tot
        d["services"][cname] = d["services"].get(cname, 0) + n
    for ip, v in np_.items():
        if ip.startswith("192.168.2.") and ip not in (HOSTS["homelab"]["ip"], HOSTS["clawhost"]["ip"], HOSTS["nas"]["ip"]):
            d = per_client.setdefault(ip, {"rx": 0, "tx": 0, "services": {}})
            d["rx"] += v.get("out", 0)
            d["tx"] += v.get("in", 0)
            d["services"]["NAS (" + _proto_of(v.get("ports", {})) + ")"] = v.get("conns", 0)
    pc_ip = "192.168.2.208"
    pc = per_client.pop(pc_ip, None)
    if pc:
        edge("pc", "nas", pc["tx"], pc["rx"], "media" if any("jellyfin" in s for s in pc["services"]) else "http", "PC fixe → services NAS",
             estimated=True, detail=[f"{s} × {n}" for s, n in sorted(pc["services"].items(), key=lambda kv: -kv[1])[:6]])
    lan_rx = sum(d["rx"] for d in per_client.values())
    lan_tx = sum(d["tx"] for d in per_client.values())
    top = sorted(per_client.items(), key=lambda kv: -(kv[1]["rx"] + kv[1]["tx"]))[:8]
    edge("lan", "nas", lan_tx, lan_rx, "http", "appareils du LAN → services NAS", estimated=True,
         detail=[f"{ip} : " + ", ".join(list(d["services"])[:3]) for ip, d in top])
    # DNS : tout le LAN -> AdGuard (homelab)
    adg = next((c for c in hcont if c["name"] == "adguardhome"), {})
    edge("lan", "homelab", adg.get("rx", 0), adg.get("tx", 0), "dns", "requêtes DNS → AdGuard", estimated=True)
    # VM Home Assistant (interface vnet du NAS)
    for name, v in (nas.get("ifaces") or {}).items():
        if name.startswith("vnet"):
            edge("nas", "ha", v.get("tx", 0), v.get("rx", 0), "domotique", f"VM Home Assistant ({name})")
            break
    # Tailscale (vue du homelab)
    for p in ts.get("peers", []):
        if not p["online"]:
            continue
        nid = {"TCASTELNAS": "nas", "JEFF-PCFIXE": "pc", "srv1045452": "vps", "clawhost": "clawhost"}.get(p["host"], "mobile")
        edge("homelab", nid if nid != "mobile" else "mobile", p["tx"], p["rx"], "tailscale",
             f"Tailscale ↔ {p['dns'] or p['host']} ({'direct' if p['direct'] else 'relais ' + (p['relay'] or '?')})", "tailscale")
    # fusion des arêtes Tailscale "mobile"
    merged = {}
    for e in edges:
        k = (e["from"], e["to"], e["proto"])
        if k in merged:
            merged[k]["ab"] += e["ab"]
            merged[k]["ba"] += e["ba"]
            merged[k]["label"] = "Tailscale ↔ appareils mobiles"
        else:
            merged[k] = e
    edges = list(merged.values())
    nodes = {
        "internet": {"label": "Internet", "sub": (STATE.get("slow", "wan") or {}).get("ip", "")},
        "box": {"label": "Routeur", "sub": "192.168.2.1"},
        "homelab": {"label": "Homelab", "sub": "192.168.2.4", "up": not hl.get("down", False) and bool(hl)},
        "nas": {"label": "NAS Unraid", "sub": "192.168.2.3", "up": bool(nas) and not nas.get("down")},
        "clawhost": {"label": "clawhost", "sub": HOSTS["clawhost"]["ip"], "up": claw.get("up", False)},
        "pc": {"label": "PC fixe", "sub": "192.168.2.208"},
        "lan": {"label": "Appareils LAN", "sub": f"{(STATE.get('slow', 'lan') or {}).get('count', 0)} vus"},
        "ha": {"label": "Home Assistant", "sub": "VM sur le NAS"},
        "vps": {"label": "VPS Hostinger", "sub": "n8n · Tailscale"},
        "mobile": {"label": "Mobiles", "sub": "iPhone · Mac · iPad"},
    }
    for p in ts.get("peers", []):
        nid = {"TCASTELNAS": "nas", "JEFF-PCFIXE": "pc", "srv1045452": "vps"}.get(p["host"])
        if nid == "vps":
            nodes["vps"]["up"] = p["online"]
    return {"nodes": nodes, "edges": edges, "clients": [{"ip": ip, **d} for ip, d in top], "vpn": vpn, "t": time.time()}


# --------------------------------------------------------------------------- diagnostics
def build_insights():
    ins = []

    def add(level, host, title, detail, action="", tag=""):
        ins.append({"level": level, "host": host, "title": title, "detail": detail, "action": action, "tag": tag})

    nas = STATE.get("live", "nas") or {}
    nslow = STATE.get("slow", "nas") or {}
    sched = STATE.get("slow", "nas_sched") or {}
    claw = STATE.get("live", "clawhost") or {}
    pub = (STATE.get("slow", "public") or {}).get("endpoints", [])
    ts = STATE.get("live", "tailscale") or {}
    hl = STATE.get("slow", "homelab") or {}
    apt = STATE.get("slow", "homelab_apt") or {}
    ncont = STATE.get("live", "nas_containers") or []
    bk = build_backups() if STATE.get("slow", "nas_backups") is not None else {"chains": []}

    # 1. IP de clawhost changée : NPM pointe encore vers l'ancienne
    old = HOSTS["clawhost"]["old_ips"]
    stale = [e for e in (sched.get("npm") or []) if e["backend"] in old]
    if stale and claw.get("up"):
        bad = [f"{e['domain']} → {e['backend']}:{e['port']}" + (f" (HTTP {next((p['code'] for p in pub if p['domain'] == e['domain']), '?')})") for e in stale]
        add("crit", "clawhost", "clawhost a changé d'IP : 192.168.2.180 → 192.168.2.5 (DHCP)",
            "Nginx Proxy Manager envoie encore " + str(len(stale)) + " domaine(s) vers l'ancienne IP : " + " ; ".join(bad) +
            ". Nexus (OPENCLAW_GATEWAY_URL / SSH) et le siteMonitor FitCoach de Homepage visent aussi 192.168.2.180.",
            "Créer un bail DHCP statique pour clawhost (MAC de enp0s31f6) sur la box, puis mettre à jour NPM, Nexus et Homepage.", "réseau")
    # 2. Tailscale clawhost
    for p in ts.get("peers", []):
        exp = p.get("key_expiry")
        if not exp:
            continue
        try:
            dt = datetime.fromisoformat(exp.replace("Z", "+00:00")).astimezone(TZ)
        except ValueError:
            continue
        days = (dt - datetime.now(dt.tzinfo)).total_seconds() / 86400
        name = p["dns"] or p["host"]
        if days < 0 and p["host"] == "clawhost":
            add("warn", "clawhost", "Tailscale de clawhost hors ligne : clé expirée",
                f"Clé expirée depuis le {dt.strftime('%d/%m/%Y')} ; clawhost n'est plus joignable à distance via Tailscale.",
                "Sur clawhost : sudo tailscale up (ré-authentification), puis désactiver l'expiration de clé dans la console Tailscale.", "tailscale")
        elif 0 <= days < 30 and p["online"]:
            add("warn", "tailscale", f"Clé Tailscale de {name} : expiration dans {int(days)} j",
                f"Expire le {dt.strftime('%d/%m/%Y %H:%M')}. Le nœud décrochera du tailnet à cette date.",
                "Console Tailscale → Machines → « Disable key expiry » pour les serveurs.", "tailscale")
    # 3. Contrôle de parité
    arr = nas.get("array") or {}
    try:
        pos, size = int(arr.get("mdResyncPos", 0)), int(arr.get("mdResyncSize", 0) or arr.get("mdResync", 0))
    except ValueError:
        pos = size = 0
    plog = sched.get("parity_log") or []
    if pos and size:
        pct = 100 * pos / size
        try:
            started = int(arr.get("sbSynced") or 0)
        except ValueError:
            started = 0
        elapsed = time.time() - started if started else 0
        speed = pos * 1024 / elapsed if elapsed > 600 else None
        eta = (size - pos) * 1024 / speed if speed else None
        hist_speed = [p["speed"] for p in plog if p.get("speed")]
        ref = sorted(hist_speed)[len(hist_speed) // 2] if hist_speed else None
        slow = speed and ref and speed < ref * 0.5
        add("warn" if slow else "info", "nas", f"Contrôle de parité en cours : {pct:.1f} %" + (" — anormalement lent" if slow else ""),
            (f"Vitesse moyenne {speed / 1e6:.1f} Mo/s" + (f" contre ~{ref / 1e6:.0f} Mo/s d'habitude" if ref else "") +
             f" : fin estimée dans {eta / 86400:.1f} jours. " if eta else "") +
            "Les disques sont partagés avec Jellyfin (transcodage), Sonarr, le mover et les sauvegardes nocturnes, ce qui ralentit tout le monde.",
            "Mettre le contrôle en pause aux heures chargées (Unraid : Main → Pause) ou installer le plugin « Parity Check Tuning » pour le restreindre à la nuit.", "stockage")
        try:
            cur_err = int(arr.get("sbSyncErrs") or 0)
        except ValueError:
            cur_err = 0
        if cur_err > 1000:
            add("crit", "nas", f"{cur_err:,} erreurs de parité dans le contrôle en cours".replace(",", " "),
                f"Déjà {cur_err} secteurs de parité incohérents à {pct:.1f} % du contrôle, bien plus que d'habitude (≤ 500 sur un contrôle complet). Typique d'un arrêt brutal du NAS pendant des écritures (le NAS a redémarré à " +
                datetime.fromtimestamp(time.time() - (sched.get("uptime") or 0), TZ).strftime("%d/%m %H:%M") + ").",
                "Laisser le contrôle finir, puis vérifier les SMART (Reallocated, Pending, CRC) et l'historique de l'onduleur pour comprendre l'arrêt.", "stockage")
    errs = [p["errors"] for p in plog[-6:]]
    if errs and sum(1 for e in errs if e > 0) >= 2:
        add("warn", "nas", "Erreurs de parité récurrentes",
            "Derniers contrôles : " + ", ".join(f"{p['date'][:11]} → {p['errors']} erreurs" for p in plog[-5:]) +
            ". Des erreurs à presque chaque contrôle indiquent des arrêts non propres (coupures), un câble SATA ou de la RAM à vérifier.",
            "Vérifier les logs SMART (CRC errors), l'onduleur (arrêt propre configuré ?) et lancer un memtest.", "stockage")
    up = sched.get("uptime") or 0
    if 0 < up < 86400 and pos:
        add("info", "nas", f"NAS redémarré il y a {up / 3600:.0f} h", "Le contrôle de parité a démarré juste après le boot : signe d'un arrêt non propre.", "", "stockage")
    # 4. Cache & disques
    disks = nslow.get("disks") or {}
    for name, d in disks.items():
        try:
            temp = int(d.get("temp", "*")) if str(d.get("temp", "*")).isdigit() else None
        except ValueError:
            temp = None
        if temp and temp >= 45:
            add("warn", "nas", f"{name} chaud : {temp} °C", "Au-delà de 45 °C la durée de vie des disques diminue.", "Vérifier la ventilation de la baie.", "stockage")
        if d.get("status") and d["status"] not in ("DISK_OK", "DISK_NP", "DISK_NP_DSBL") and d.get("status") != "":
            add("crit", "nas", f"{name} : {d['status']}", "Disque en défaut ou désactivé.", "Voir Main dans Unraid.", "stockage")
        try:
            errs_d = int(d.get("numErrors", 0))
        except ValueError:
            errs_d = 0
        if errs_d > 0:
            add("warn", "nas", f"{name} : {errs_d} erreurs de lecture/écriture", "", "", "stockage")
    for df in sched.get("df") or []:
        pct = 100 * df["used"] / df["size"] if df["size"] else 0
        if df["target"] == "/mnt/cache" and pct > 80:
            add("warn", "nas", f"Cache NVMe à {pct:.0f} %", "Le mover ne tourne qu'à 04:00 ; un gros téléchargement peut remplir le cache et bloquer les conteneurs (docker.img, appdata).",
                "Vérifier les partages en « cache: yes » volumineux (Temp, data) ou lancer le mover.", "stockage")
        if df["target"] == "/var/lib/docker" and pct > 80:
            add("warn", "nas", f"Image Docker à {pct:.0f} %", "docker.img presque plein : risque de plantage des conteneurs.", "Supprimer les images inutilisées.", "docker")
    # 5. Sauvegardes
    for c in bk["chains"]:
        if c["status"] == "crit":
            add("crit", c["from"], f"Sauvegarde {c['label']} : " + ("absente" if not c.get("last_time") else f"dernière il y a {c.get('age_h', 0):.0f} h"),
                c.get("problem") or f"Destination {c['dest']}.", "Activer/planifier la sauvegarde (ex. plugin Appdata Backup déjà installé)." if c["id"] == "appdata" else "", "backup")
        elif c["status"] == "warn":
            add("warn", c["from"], f"Sauvegarde {c['label']} en retard ({c.get('age_h', 0):.0f} h)", c["dest"], "", "backup")
        if c.get("size_delta") is not None and abs(c["size_delta"]) > 40 and c["status"] == "ok":
            add("info", c["from"], f"Taille de la sauvegarde {c['label']} : {c['size_delta']:+.0f} % vs moyenne", "Variation importante : à vérifier si inattendu.", "", "backup")
    add("warn", "nas", "Aucune copie hors site", "Toutes les sauvegardes (homelab, clawhost, Forgejo) finissent sur le même NAS : un incident (vol, incendie, ransomware, double panne disque) les emporte avec les originaux. Règle 3-2-1 non respectée.",
        "Ajouter une réplication chiffrée vers un stockage externe (rclone/restic vers Backblaze B2, Hetzner Storage Box, ou le VPS Hostinger).", "backup")
    # 6. Sécurité : bases de données exposées sur le LAN
    dbs = []
    for c in ncont:
        img = c.get("image", "")
        if re.search(r"postgres|pgvector|timescale|redis|mariadb|mysql|mongo", img) and "0.0.0.0:" in (c.get("ports") or ""):
            ports = sorted(set(re.findall(r"0\.0\.0\.0:(\d+)->", c["ports"])))
            dbs.append(f"{c['name']} (:{','.join(ports)})")
    if dbs:
        add("warn", "nas", f"{len(dbs)} bases de données exposées sur tout le LAN",
            "Publiées sur 0.0.0.0 : " + ", ".join(dbs) + ". Tout appareil du réseau (TV, IoT, invités) peut les atteindre ; les Redis n'ont souvent pas de mot de passe.",
            "Publier ces ports sur 127.0.0.1 ou ne pas les publier (réseau Docker interne).", "sécurité")
    # 7. Conteneurs en difficulté
    for c in ncont:
        if c.get("health") == "unhealthy":
            add("crit", "nas", f"{c['name']} : unhealthy", c.get("status", ""), "", "docker")
        if c["state"] == "restarting":
            add("crit", "nas", f"{c['name']} redémarre en boucle", c.get("status", ""), "", "docker")
        if c["state"] == "exited" and c.get("exit") not in ("0", 0, None, ""):
            add("warn", "nas", f"{c['name']} arrêté (code {c.get('exit')})", c.get("status", ""), "", "docker")
    # 8. Auto-update des conteneurs
    if any("updateDocker.php" in j.get("command", "") for j in sched.get("crons", [])):
        latest = sum(1 for c in ncont if c.get("image", "").endswith(":latest") or ":" not in c.get("image", "").split("/")[-1])
        add("info", "nas", "Mise à jour automatique des conteneurs chaque jour à 07:00",
            f"{latest} conteneurs suivent un tag « latest » : une mise à jour cassante peut arriver sans prévenir. Le journal d'événements de ce dashboard trace les redémarrages.",
            "Épingler les versions des services critiques (Immich, Vaultwarden, bases).", "docker")
    # 9. Homelab
    if hl.get("reboot_required"):
        add("info", "homelab", "Redémarrage du homelab en attente", "Paquets : " + ", ".join(hl.get("reboot_pkgs") or ["noyau"]) + ". Le noyau en cours reste l'ancien.",
            "Planifier un reboot (DNS du réseau indisponible ~1 min).", "système")
    if apt.get("pending"):
        add("info", "homelab", f"{apt['pending']} mises à jour en attente sur le homelab", ", ".join(apt.get("packages", [])[:8]), "", "système")
    # 9 bis. clawhost (inventaire SSH en lecture seule)
    cs = STATE.get("slow", "claw_ssh") or {}
    if cs.get("ok"):
        if cs.get("reboot_required"):
            add("info", "clawhost", "Redémarrage de clawhost en attente", f"Noyau en cours : {cs.get('kernel')}.",
                "Planifier un reboot de clawhost (OpenClaw, Netscan et FitCoach indisponibles ~2 min).", "système")
        if cs.get("n_upgradable"):
            add("info", "clawhost", f"{cs['n_upgradable']} mises à jour en attente sur clawhost", ", ".join(cs.get("upgradable", [])[:8]),
                "Sur clawhost : sudo apt update && sudo apt upgrade", "système")
        for u in cs.get("failed_units", [])[:5]:
            add("warn", "clawhost", f"Service en échec sur clawhost : {u}", "systemctl --failed", f"Sur clawhost : systemctl status {u}", "système")
        for d in cs.get("df", []):
            if d["size"] and d["used"] / d["size"] > 0.9:
                add("warn", "clawhost", f"Disque {d['mount']} de clawhost plein à {round(100 * d['used'] / d['size'])} %", d["fs"], "Libérer de l'espace.", "stockage")
    elif cs.get("installed") and cs.get("error"):
        todo = "Permission denied" in cs["error"]
        add("info", "clawhost", "Accès lecture seule à clawhost à installer" if todo else "Accès SSH lecture seule de clawhost en échec",
            "Sans lui, clawhost n'est vu que par des sondes réseau (ni mises à jour, ni services, ni disques)." if todo else cs["error"],
            "Depuis le homelab : ssh -p 2211 openclaw@192.168.2.5 'bash -s' < ~/infra-dashboard/tools/clawhost-ro-setup.sh", "système")
    # 9 ter. NetScan (outil de cartographie du LAN, sur clawhost)
    for it in ((STATE.get("slow", "netscan") or {}).get("digest") or {}).get("issues") or []:
        add(it["level"], "clawhost", it["title"], it["detail"], it.get("fix", ""), "réseau")
    # 10. Onduleur
    ups = nslow.get("ups") or {}
    if ups.get("STATUS") and "ONLINE" not in ups["STATUS"]:
        add("crit", "nas", f"Onduleur : {ups['STATUS']}", f"Batterie {ups.get('BCHARGE')}, autonomie {ups.get('TIMELEFT')}", "", "énergie")
    if ups and ups.get("LOADPCT", "").startswith("0.0"):
        add("info", "nas", "Onduleur : charge non remontée (0 %)", f"{ups.get('MODEL', 'UPS')} en ligne, batterie {ups.get('BCHARGE', '?')}, autonomie {ups.get('TIMELEFT', '?')}. La charge réelle n'est pas mesurée : impossible de savoir ce qui est protégé.",
            "Vérifier que le homelab (DNS de tout le réseau) et la box sont aussi sur l'onduleur, et que l'arrêt propre du NAS est configuré.", "énergie")
    # 11. Endpoints publics en erreur (hors ancienne IP clawhost, traitée plus haut)
    published = set()
    for c in ncont:
        published.update(int(p) for p in re.findall(r":(\d+)->", c.get("ports") or ""))
    orphans, broken, dnsless = [], [], []
    for e in pub:
        if e["ok"] or e["backend"] in old:
            continue
        port = int(e["port"]) if str(e["port"]).isdigit() else 0
        if e.get("issuer") == "gaierror":
            dnsless.append(f"{e['domain']} → {e['backend']}:{e['port']}")
        elif e.get("code") is None and e.get("ms", 0) < 100:
            orphans.append(f"{e['domain']} : injoignable (connexion refusée)")
        elif e["backend"] == HOSTS["nas"]["ip"] and port and port not in published:
            orphans.append(f"{e['domain']} → :{port} : aucun conteneur ne publie ce port (HTTP {e.get('code')})")
        else:
            broken.append(f"{e['domain']} → {e['backend']}:{e['port']} (HTTP {e.get('code') or 'timeout'})")
    if dnsless:
        add("warn", "internet", f"{len(dnsless)} proxy host(s) NPM sans DNS mais toujours actif(s)",
            " ; ".join(dnsless) + ". Retirer l'enregistrement DNS ne ferme pas l'accès : NPM sert toujours ces hôtes à quiconque "
            "envoie le bon nom (Host/SNI) vers l'IP publique, et le nom reste visible dans les journaux Certificate Transparency.",
            "Supprimer le proxy host dans Nginx Proxy Manager (http://192.168.2.3:81) ou lui associer une Access List.", "sécurité")
    if broken:
        add("crit", "internet", f"{len(broken)} domaine(s) public(s) en erreur", " ; ".join(broken) + ".",
            "Vérifier le service cible (conteneur arrêté, port changé) dans Nginx Proxy Manager.", "public")
    if orphans:
        add("warn", "internet", f"{len(orphans)} hôte(s) Nginx Proxy Manager orphelin(s)", " ; ".join(orphans) +
            ". Ces domaines sont publiés sur Internet mais ne mènent plus nulle part (n8n tourne désormais sur le VPS Hostinger).",
            "Supprimer ou corriger ces proxy hosts dans NPM (http://192.168.2.3:81).", "public")
    for e in pub:
        if e.get("cert_days") is not None and e["cert_days"] < 15:
            add("warn", "internet", f"Certificat {e['domain']} expire dans {e['cert_days']} j", e.get("issuer", ""), "Vérifier le renouvellement Let's Encrypt dans NPM.", "public")
    # 11 bis. Ollama sans GPU (après une recréation par l'auto-update, le template Unraid perd --runtime=nvidia)
    ort = STATE.get("slow", "ollama_runtime") or {}
    if ort and ort.get("gpu") is False:
        add("warn", "nas", "Ollama tourne sans le GPU",
            f"Le conteneur {ort.get('container', 'ollama')} (recréé le {ort.get('started', '')[:16].replace('T', ' ')} UTC) utilise le runtime "
            f"« {ort.get('runtime') or '?'} » sans accès à la RTX 3060 : chaque requête IA (J.Prod, Nexus, analyse InfraDash…) part sur le CPU du NAS, "
            "lente et très gourmande. L'auto-update de 07:00 recrée les conteneurs avec leur template, qui ne contient pas l'option GPU.",
            "Unraid → Docker → ollama → Edit → Extra Parameters : --runtime=nvidia (et NVIDIA_VISIBLE_DEVICES=all), puis Apply.", "ia")
    # 12. Liens Homepage morts
    hl_links = (STATE.get("slow", "homepage_links") or {}).get("links") or []
    listen_local = {p["port"] for p in (hl.get("listen") or []) if p["addr"].startswith("127.")}
    dead = []
    for l in hl_links:
        if l["ok"]:
            continue
        why = "ne répond pas"
        if l["host"] == HOSTS["homelab"]["ip"] and l["port"] in listen_local:
            why = "écoute seulement sur 127.0.0.1 depuis le durcissement du homelab"
        elif l["host"] in old or l["host"] == "192.168.2.164":
            why = "ancienne IP" + (" (Home Assistant est en 192.168.2.240)" if l["host"] == "192.168.2.164" else " (clawhost est en 192.168.2.5)")
        dead.append(f"{l['host']}:{l['port']} ({why})")
    if dead:
        add("warn", "nas", f"{len(dead)} lien(s) morts sur la page Homepage",
            "Tuiles de dashboard.jposyno.eu qui ne mènent plus nulle part : " + " ; ".join(dead) + ".",
            "Corriger /mnt/user/appdata/homepage/services.yaml (ou retirer les tuiles VictoriaMetrics/cAdvisor, internes au homelab).", "réseau")
    # 13. Créneau chargé
    jobs = build_jobs()
    if jobs["peak"] and len(jobs["peak"][0][1]) >= 4:
        h, names = jobs["peak"][0]
        add("info", "nas", f"Heure de pointe des tâches lourdes : {h}", f"{len(names)} tâches disque/réseau démarrent dans ce créneau : " + ", ".join(sorted(set(names))[:8]) +
            ". Elles se disputent les disques de l'array (et le contrôle de parité s'il tourne).", "Étaler les tâches (ex. Forgejo à 02:30, ArrMada à 05:00) pour raccourcir la fenêtre nocturne.", "planning")
    order = {"crit": 0, "warn": 1, "info": 2}
    ins.sort(key=lambda i: order.get(i["level"], 3))
    return ins
