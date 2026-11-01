"""Collecte du NAS Unraid via SSH (commandes fixes en lecture seule, connexion persistante)."""
import json
import re
import time

from .config import CONTAINER_INFO, HOSTS
from .procfs import SECTIONS_CMD, HostMetrics, split_sections
from .ssh import SSH
from .state import STATE
from .util import RateTracker, Ring, redact

H = HOSTS["nas"]
SSHC = SSH(H["ssh"]["user"], H["ssh"]["host"], H["ssh"]["port"])
HM = HostMetrics()
RATES = RateTracker()
CHIST = {}
CTX = {"pids": {}, "ip2name": {}, "containers": {}, "netns_owner": {}}
_prev = {"containers": None, "notif": set(), "online": None, "backups": None, "smb": None}

CLAW_GLOB = "clawhost/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]_[0-9][0-9][0-9][0-9]/"   # dossiers datés de sauvegarde clawhost

INI_KEYS = ("mdState|mdResync|mdResyncPos|mdResyncSize|mdResyncDt|mdResyncDb|mdResyncAction|sbSynced|sbSynced2|"
            "sbSyncErrs|sbSyncExit|mdNumDisks|mdNumInvalid|mdNumMissing|fsState|shareMoverActive|version|NAME|mdColor|"
            "shareCacheEnabled|fsNumMounted")


def parse_ini(lines):
    out, cur = {}, None
    for line in lines:
        line = line.strip()
        m = re.match(r'^\["?([^"\]]+)"?\]$', line)
        if m:
            cur = m.group(1)
            out[cur] = {}
        elif "=" in line:
            k, v = line.split("=", 1)
            v = v.strip('"')
            if cur is None:
                out[k] = v
            else:
                out[cur][k] = v
    return out


def _alive(ok):
    if _prev["online"] is not None and _prev["online"] != ok:
        STATE.event("ok" if ok else "crit", "nas", "NAS " + ("joignable" if ok else "injoignable (SSH)"), SSHC.last_error, "host")
    _prev["online"] = ok


def fast():
    pids = {k: v for k, v in CTX["pids"].items() if str(v).isdigit() and int(v) > 0}
    # 3 processus au total (grep -H garde le nom de fichier) au lieu d'un par conteneur
    cg = "echo @@cg; grep -H usage_usec /sys/fs/cgroup/docker/*/cpu.stat 2>/dev/null; grep -H . /sys/fs/cgroup/docker/*/memory.current 2>/dev/null"
    plist = sorted(set(int(p) for p in pids.values()))
    cnet = "echo @@cnet" + (("; grep -H : " + " ".join(f"/proc/{p}/net/dev" for p in plist) + " 2>/dev/null") if plist else "")
    cmd = (SECTIONS_CMD + f"; echo @@var; grep -E '^({INI_KEYS})=' /var/local/emhttp/var.ini; " + cg + "; " + cnet +
           "; echo @@ss; ss -tniH state established | awk 'NR%2==1{l=$(NF-1);p=$NF;next}{a=0;r=0;"
           "for(i=1;i<=NF;i++){if($i~/^bytes_acked:/)a=substr($i,13);if($i~/^bytes_received:/)r=substr($i,16)} print l,p,a,r}'")
    out = SSHC.run(cmd, timeout=12)
    _alive(out is not None)
    if not out or "@@stat" not in out:
        STATE.set("live", "nas", {"down": True, "error": SSHC.last_error, "t": time.time()})
        return
    sec = split_sections(out)
    m = HM.update(sec)
    var = parse_ini(sec.get("var", []))
    m["array"] = var
    m["hist"] = {k: r.list()[-150:] for k, r in HM.hist.items()}
    now = time.time()
    # CPU / mémoire par conteneur (cgroup v2)
    cstats = {}
    for line in sec.get("cg", []):
        m_ = re.match(r"^/sys/fs/cgroup/docker/([0-9a-f]{12})[0-9a-f]*/(cpu\.stat|memory\.current):(?:usage_usec )?(\d+)", line)
        if not m_:
            continue
        d = cstats.setdefault(m_.group(1), {"cpu": 0, "mem": 0})
        if m_.group(2) == "cpu.stat":
            d["cpu"] = round(RATES.rate("cg:" + m_.group(1), int(m_.group(3)), now) / 1e6 * 100, 1)
        else:
            d["mem"] = int(m_.group(3))
    # Réseau par conteneur (interfaces de son namespace)
    cnet = {}
    for line in sec.get("cnet", []):
        m_ = re.match(r"^/proc/(\d+)/net/dev:\s*([^:\s]+):\s*(.*)$", line)
        if not m_ or m_.group(2) == "lo":
            continue
        f = m_.group(3).split()
        c_ = cnet.setdefault(m_.group(1), [0, 0])
        c_[0] += int(f[0])
        c_[1] += int(f[8])
    netrate = {}
    for pid, (rxb, txb) in cnet.items():
        netrate[pid] = (RATES.rate("nrx:" + pid, rxb, now), RATES.rate("ntx:" + pid, txb, now), rxb, txb)
    clist = []
    for name, c in CTX["containers"].items():
        st = cstats.get(c["id"][:12], {})
        pid = str(CTX["pids"].get(name, ""))
        nr = netrate.get(pid) if c.get("netmode") not in ("host",) and CTX["netns_owner"].get(pid) == name else None
        h = CHIST.setdefault(name, {"cpu": Ring(120), "net": Ring(120)})
        if c["state"] == "running":
            h["cpu"].add(now, st.get("cpu", 0))
            h["net"].add(now, round(nr[0] + nr[1]) if nr else 0)
        desc, cat = CONTAINER_INFO.get(name, ("", "autre"))
        clist.append({**c, "cpu": st.get("cpu", 0), "mem": st.get("mem", 0),
                      "rx": round(nr[0]) if nr else 0, "tx": round(nr[1]) if nr else 0,
                      "rx_total": nr[2] if nr else 0, "tx_total": nr[3] if nr else 0,
                      "desc": c.get("desc") or desc, "cat": cat,
                      "spark": [v for _, v in h["cpu"].list()[-40:]], "nspark": [v for _, v in h["net"].list()[-40:]]})
    clist.sort(key=lambda c: (c["state"] != "running", -c["cpu"]))
    m["n_containers"] = len(clist)
    STATE.set("live", "nas", m)
    STATE.set("live", "nas_containers", clist)
    # Flux TCP du NAS (sockets hôte)
    agg = {}
    for line in sec.get("ss", []):
        p = line.split()
        if len(p) != 4:
            continue
        local, peer = p[0], p[1]
        pip, pport = peer.rsplit(":", 1)
        lport = local.rsplit(":", 1)[1]
        pip = pip.strip("[]").replace("::ffff:", "")
        k = f"{pip}|{lport}|{pport}"
        ro = RATES.rate("so" + k, int(p[2] or 0), now)
        ri = RATES.rate("si" + k, int(p[3] or 0), now)
        a = agg.setdefault(pip, {"out": 0.0, "in": 0.0, "conns": 0, "ports": {}})
        a["out"] += ro
        a["in"] += ri
        a["conns"] += 1
        lp, pp = int(lport) if lport.isdigit() else 99999, int(pport) if pport.isdigit() else 99999
        svc = min(lp, pp)
        a["ports"][svc] = a["ports"].get(svc, 0) + 1
    STATE.set("live", "nas_peers", agg)


def conntrack():
    awk = ("awk '{p=$3;st=\"\";s=\"\";d=\"\";dp=\"\";rs=\"\";n=0;for(i=1;i<=NF;i++){if($i~/^src=/){n++;"
           "if(n==1)s=substr($i,5);else if(n==2)rs=substr($i,5)}else if($i~/^dst=/&&d==\"\")d=substr($i,5);"
           "else if($i~/^dport=/&&dp==\"\")dp=substr($i,7);else if($i==\"ESTABLISHED\")st=\"E\"}"
           "if(p==\"udp\"||st==\"E\")c[p\" \"s\" \"d\" \"dp\" \"rs]++}END{for(k in c)print c[k],k}' /proc/net/nf_conntrack")
    out = SSHC.run(awk, timeout=10)
    if out is None:
        return
    flows = []
    for line in out.splitlines():
        p = line.split()
        if len(p) == 6:
            flows.append({"n": int(p[0]), "proto": p[1], "src": p[2], "dst": p[3], "dport": int(p[4]) if p[4].isdigit() else 0, "rsrc": p[5]})
    STATE.set("live", "nas_conntrack", flows)


def slow():
    cmd = ("echo @@disks; cat /var/local/emhttp/disks.ini; echo @@shares; cat /var/local/emhttp/shares.ini; "
           "echo @@docker; docker ps -a --format '{{json .}}'; "
           "echo @@inspect; docker inspect $(docker ps -aq) --format "
           "'{{.Name}}|{{.State.Pid}}|{{.HostConfig.NetworkMode}}|{{.State.StartedAt}}|{{.RestartCount}}|"
           "|{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}},{{end}}|{{.Id}}|{{.State.Status}}|{{.State.ExitCode}}'; "
           "echo @@netns; for p in $(docker inspect $(docker ps -q) --format '{{.State.Pid}}'); do echo \"$p $(readlink /proc/$p/ns/net)\"; done; "
           "echo @@ups; apcaccess 2>/dev/null; echo @@gpu; nvidia-smi --query-gpu=name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,fan.speed --format=csv,noheader,nounits 2>/dev/null; "
           "echo @@gpuproc; nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits 2>/dev/null; "
           "echo @@sensors; sensors -j 2>/dev/null | tr -d '\\n'; echo; echo @@vms; virsh list --all 2>/dev/null; "
           "echo @@ts; tailscale status --json 2>/dev/null | tr -d '\\n'; echo; "
           "echo @@notif; for f in /tmp/notifications/unread/*.notify; do [ -f \"$f\" ] && echo \"$(basename $f)|$(grep -E '^(timestamp|event|subject|description|importance)=' $f | tr '\\n' '|')\"; done; "
           "echo @@smb; smbstatus -S 2>/dev/null | tail -n +4; echo @@smbu; smbstatus -b 2>/dev/null | tail -n +5; "
           "echo @@cpuinfo; grep -m1 'model name' /proc/cpuinfo")
    out = SSHC.run(cmd, timeout=40)
    if out is None:
        return
    sec = split_sections(out)
    disks = parse_ini(sec.get("disks", []))
    shares = parse_ini(sec.get("shares", []))
    # Conteneurs
    cont = {}
    for line in sec.get("docker", []):
        try:
            j = json.loads(line)
        except ValueError:
            continue
        labels = dict(kv.split("=", 1) for kv in (j.get("Labels") or "").split(",") if "=" in kv)
        cont[j["Names"]] = {"name": j["Names"], "image": j["Image"], "status": j["Status"], "state": j["State"],
                            "ports": j.get("Ports", ""), "project": labels.get("com.docker.compose.project", ""),
                            "networks": j.get("Networks", ""), "health": j.get("HealthStatus", ""), "id": j["ID"]}
    pids, ip2name = {}, {}
    for line in sec.get("inspect", []):
        p = line.split("|")
        if len(p) < 10:
            continue
        name = p[0].lstrip("/")
        if name in cont:
            cont[name].update({"pid": int(p[1]) if p[1].isdigit() else 0, "netmode": p[2], "started": p[3],
                               "restarts": int(p[4]) if p[4].isdigit() else 0, "health": p[5] or cont[name]["health"],
                               "ips": [x for x in p[6].split(",") if x], "id": p[7], "exit": p[9]})
            if p[1].isdigit() and int(p[1]) > 0:
                pids[name] = int(p[1])
            for x in p[6].split(","):
                if "=" in x and x.split("=")[1]:
                    ip2name[x.split("=")[1]] = name
    # Un seul conteneur "propriétaire" par namespace réseau (évite les doublons de débit)
    ns_seen, owner = {}, {}
    host_ns = None
    pid2name = {v: k for k, v in pids.items()}
    for line in sec.get("netns", []):
        p = line.split()
        if len(p) == 2 and p[0].isdigit():
            nm = pid2name.get(int(p[0]))
            if nm and cont.get(nm, {}).get("netmode") == "host":
                host_ns = p[1]
                continue
            if p[1] not in ns_seen and p[1] != host_ns:
                ns_seen[p[1]] = nm
                owner[p[0]] = nm
    CTX.update({"pids": pids, "ip2name": ip2name, "containers": cont, "netns_owner": owner})
    # Événements conteneurs
    states = {n: (c["state"], c.get("started")) for n, c in cont.items()}
    if _prev["containers"] is not None:
        for n, (st, started) in states.items():
            old = _prev["containers"].get(n)
            if old is None:
                STATE.event("info", "nas", f"Nouveau conteneur : {n}", cont[n]["image"], "container")
            elif old[0] != st:
                lvl = "ok" if st == "running" else "crit"
                STATE.event(lvl, "nas", f"{n} : {old[0]} → {st}", cont[n]["status"], "container")
            elif started and old[1] and started != old[1] and st == "running":
                STATE.event("warn", "nas", f"{n} a redémarré", cont[n]["status"], "container")
        for n in _prev["containers"]:
            if n not in states:
                STATE.event("warn", "nas", f"Conteneur supprimé : {n}", "", "container")
    _prev["containers"] = states
    # UPS
    ups = {}
    for line in sec.get("ups", []):
        if ":" in line:
            k, v = line.split(":", 1)
            ups[k.strip()] = v.strip()
    # GPU
    gpu = None
    if sec.get("gpu"):
        g = [x.strip() for x in sec["gpu"][0].split(",")]
        if len(g) >= 6:
            def num(x):
                try:
                    return float(x)
                except ValueError:
                    return None
            gpu = {"name": g[0], "temp": num(g[1]), "util": num(g[2]), "mem_used": num(g[3]), "mem_total": num(g[4]),
                   "power": num(g[5]), "fan": num(g[6]) if len(g) > 6 else None,
                   "procs": [l.split(",")[1].strip() for l in sec.get("gpuproc", []) if "," in l]}
    # Capteurs
    sensors = {}
    try:
        sj = json.loads("".join(sec.get("sensors", [])) or "{}")
        for chip, vals in sj.items():
            for lbl, d in vals.items():
                if isinstance(d, dict):
                    for k, v in d.items():
                        if k.endswith("_input") and isinstance(v, (int, float)):
                            if k.startswith("temp"):
                                sensors[f"{chip}:{lbl}"] = round(v, 1)
                            elif k.startswith("fan") and v > 0:
                                sensors[f"fan:{chip}:{lbl}"] = round(v)
    except ValueError:
        pass
    # VMs
    vms = []
    for line in sec.get("vms", [])[2:]:
        p = line.split(None, 2)
        if len(p) == 3:
            vms.append({"id": p[0], "name": p[1], "state": p[2].strip()})
    # Tailscale (vue du NAS)
    try:
        ts = json.loads("".join(sec.get("ts", [])) or "{}")
        tsp = [{"host": v.get("HostName"), "online": v.get("Online"), "rx": v.get("RxBytes", 0), "tx": v.get("TxBytes", 0),
                "addr": v.get("CurAddr"), "relay": v.get("Relay"), "ips": v.get("TailscaleIPs", [])[:1]}
               for v in (ts.get("Peer") or {}).values()]
    except ValueError:
        tsp = []
    # Notifications Unraid
    notifs = []
    for line in sec.get("notif", []):
        parts = line.split("|")
        d = {"file": parts[0]}
        for kv in parts[1:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                d[k] = v.strip('"')
        notifs.append(d)
    names = {n["file"] for n in notifs}
    for n in notifs:
        if _prev["notif"] and n["file"] not in _prev["notif"]:
            lvl = {"alert": "crit", "warning": "warn"}.get(n.get("importance"), "info")
            STATE.event(lvl, "nas", n.get("subject", n["file"]), n.get("description", ""), "unraid")
    _prev["notif"] = names or _prev["notif"]
    # Sessions SMB
    smb_shares = []
    for line in sec.get("smb", []):
        p = line.split()
        if len(p) >= 3 and p[0] != "IPC$":
            smb_shares.append({"share": p[0], "pid": p[1], "machine": p[2], "since": " ".join(p[3:8])})
    smb_users = []
    for line in sec.get("smbu", []):
        p = line.split()
        if len(p) >= 4 and p[0].isdigit():
            smb_users.append({"pid": p[0], "user": p[1], "machine": p[3]})
    STATE.set("slow", "nas", {
        "disks": disks, "shares": {k: {kk: v.get(kk) for kk in ("name", "comment", "free", "used", "useCache", "cachePool", "color", "allocator")}
                                   for k, v in shares.items() if isinstance(v, dict)},
        "ups": ups, "gpu": gpu, "sensors": sensors, "vms": vms, "tailscale": tsp, "notifications": notifs,
        "smb_shares": smb_shares, "smb_users": smb_users,
        "cpu_model": (sec.get("cpuinfo") or [""])[0].split(":", 1)[-1].strip(), "t": time.time()})


def very_slow():
    cmd = ("echo @@crond; cat /etc/cron.d/root; echo @@crontab; crontab -l 2>/dev/null; "
           "echo @@usched; cat /boot/config/plugins/user.scripts/schedule.json 2>/dev/null | tr -d '\\n'; echo; "
           "echo @@uscripts; for d in /boot/config/plugins/user.scripts/scripts/*/; do n=$(basename \"$d\"); "
           "echo \"$n|$(head -c 300 \"$d/description\" 2>/dev/null | tr '\\n|' '  ')|$(grep -m1 -oP '^#description=\\K.*' \"$d/script\" 2>/dev/null)\"; done; "
           "echo @@runparts; for d in hourly daily weekly monthly; do echo \"$d:$(ls /etc/cron.$d 2>/dev/null | tr '\\n' ' ')\"; done; "
           "echo @@parity; tail -n 12 /boot/config/parity-checks.log 2>/dev/null; "
           "echo @@npm; for f in /mnt/user/appdata/NginxProxyManager/nginx/proxy_host/*.conf; do "
           "sn=$(grep -m1 -oP 'server_name\\s+\\K[^;]+' $f); fw=$(grep -m1 -oP 'set \\$server\\s+\"?\\K[^\";]+' $f); "
           "fp=$(grep -m1 -oP 'set \\$port\\s+\\K[^;]+' $f); ssl=$(grep -c 'ssl_certificate ' $f); echo \"$sn|$fw|$fp|$ssl\"; done; "
           "echo @@homepage; grep -ohE 'https?://192\\.168\\.[0-9.]+:[0-9]+' /mnt/user/appdata/homepage/services.yaml 2>/dev/null | sort -u; "
           "echo @@uptime; cat /proc/uptime; echo @@dockerdf; df -B1 /var/lib/docker /mnt/cache /boot / 2>/dev/null | tail -n +2")
    out = SSHC.run(cmd, timeout=30)
    if out is None:
        return
    sec = split_sections(out)
    crons = []
    for src, key in (("/etc/cron.d/root", "crond"), ("crontab root", "crontab")):
        for line in sec.get(key, []):
            line = line.strip()
            if not line or line.startswith("#") or re.match(r"^[A-Z_]+=", line):
                continue
            f = line.split()
            if len(f) < 6:
                continue
            sched = " ".join(f[:5])
            crons.append({"schedule": sched, "user": "root", "command": redact(" ".join(f[5:])), "source": src})
    try:
        usched = json.loads("".join(sec.get("usched", [])) or "{}")
    except ValueError:
        usched = {}
    uscripts = []
    descs = {}
    for line in sec.get("uscripts", []):
        p = line.split("|")
        if p and p[0]:
            descs[p[0]] = (p[1].strip() if len(p) > 1 else "") or (p[2].strip() if len(p) > 2 else "")
    for path, s in usched.items():
        name = path.split("/scripts/")[-1].rsplit("/script", 1)[0]
        uscripts.append({"name": name, "frequency": s.get("frequency"), "custom": s.get("custom"), "desc": descs.get(name, "")})
    for name in descs:
        if not any(u["name"] == name for u in uscripts):
            uscripts.append({"name": name, "frequency": "disabled", "custom": "", "desc": descs[name]})
    runparts = {}
    for line in sec.get("runparts", []):
        if ":" in line:
            k, v = line.split(":", 1)
            runparts[k] = v.split()
    parity = []
    for line in sec.get("parity", []):
        p = line.split("|")
        if len(p) >= 5:
            try:
                parity.append({"date": p[0], "duration": int(p[1]), "speed": int(p[2]), "exit": int(p[3]), "errors": int(p[4]),
                               "action": p[5] if len(p) > 5 else ""})
            except ValueError:
                continue
    npm = []
    for line in sec.get("npm", []):
        p = line.split("|")
        if len(p) >= 3 and p[0]:
            npm.append({"domain": p[0].split()[0], "backend": p[1], "port": p[2], "ssl": (p[3] if len(p) > 3 else "0") != "0"})
    up = float(sec.get("uptime", ["0"])[0].split()[0]) if sec.get("uptime") else 0
    dfs = []
    for line in sec.get("dockerdf", []):
        p = line.split()
        if len(p) >= 6:
            dfs.append({"source": p[0], "size": int(p[1]), "used": int(p[2]), "avail": int(p[3]), "target": p[5]})
    homepage = sorted({l.strip() for l in sec.get("homepage", []) if l.strip().startswith("http")})
    STATE.set("slow", "nas_sched", {"crons": crons, "user_scripts": uscripts, "run_parts": runparts, "parity_log": parity,
                                    "npm": npm, "uptime": up, "df": dfs, "homepage_urls": homepage, "t": time.time()})


def backups():
    """Inventaire des sauvegardes sur le NAS (métadonnées seulement, servies depuis le cache disque)."""
    # Sécurité : aucun nom de dossier lu sur le NAS n'est découpé par le shell ; seuls les dossiers datés
    # (AAAA-MM-JJ_HHMM, que des chiffres) sont parcourus, tout est entre guillemets et préfixé par ./ (jamais pris pour une option).
    cmd = ("cd /mnt/user/backups 2>/dev/null || exit 0; "
           f"L=; for x in {CLAW_GLOB}; do [ -d \"$x\" ] && L=$x; done; "
           "echo @@homelab; find ./homelab-netnode -maxdepth 1 -type f -printf '%f|%s|%T@\\n' 2>/dev/null; "
           "echo @@forgejo; find ./forgejo -maxdepth 1 -type f -printf '%f|%s|%T@\\n' 2>/dev/null; "
           f"echo @@clawhost; set -- {CLAW_GLOB}; [ $# -gt 40 ] && shift $(($# - 40)); for d in \"$@\"; do [ -d \"$d\" ] || continue; "
           "echo \"$(basename -- \"$d\")|$(find \"./$d\" -type f -printf '%s\\n' | awk '{s+=$1}END{print s+0}')|$(stat -c %Y -- \"$d\")|$(ls -- \"$d\" | tr '\\n|' '  ')\"; done; "
           "echo @@appdata; find ./appdata -maxdepth 3 -type f -printf '%P|%s|%T@\\n' 2>/dev/null | head -50; "
           "echo @@root; find . -maxdepth 1 -type f -printf '%f|%s|%T@\\n' | awk -F'|' '{n++; s+=$2; if($3>m)m=$3} END{print n+0\"|\"s+0\"|\"m+0}'; "
           "echo @@invent; [ -n \"$L\" ] && cat -- \"./${L}inventaire-systeme.txt\" 2>/dev/null; "
           "echo @@clawdocker; [ -n \"$L\" ] && cat -- \"./${L}images-docker.txt\" 2>/dev/null")
    out = SSHC.run(cmd, timeout=60)
    if out is None or "@@homelab" not in out:   # array arrêté ou échec : ne pas publier un inventaire vide
        return
    sec = split_sections(out)

    def files(key):
        res = []
        for line in sec.get(key, []):
            p = line.split("|")
            if len(p) >= 3:
                try:
                    res.append({"name": p[0], "size": int(p[1]), "mtime": float(p[2])})
                except ValueError:
                    pass
        return sorted(res, key=lambda x: x["mtime"])
    claw = []
    for line in sec.get("clawhost", []):
        p = line.split("|")
        if len(p) >= 3 and re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{4}", p[0]):
            try:
                claw.append({"name": p[0], "size": int(p[1]), "mtime": float(p[2]), "files": p[3].split() if len(p) > 3 else []})
            except ValueError:
                pass
    root = (sec.get("root") or ["0|0|0"])[0].split("|")
    res = {"homelab-netnode": files("homelab"), "forgejo": files("forgejo"), "clawhost": claw,
           "appdata": files("appdata"),
           "root_files": {"count": int(root[0]), "size": int(root[1]), "newest": float(root[2])} if len(root) == 3 else {},
           "claw_inventory": "\n".join(sec.get("invent", [])), "claw_images": sec.get("clawdocker", []), "t": time.time()}
    # Événement quand une nouvelle sauvegarde apparaît
    newest = {k: (v[-1]["name"] if v else None) for k, v in res.items() if isinstance(v, list) and k != "claw_images"}
    if _prev["backups"]:
        for k, n in newest.items():
            if n and n != _prev["backups"].get(k):
                STATE.event("ok", "nas", f"Nouvelle sauvegarde {k}", n, "backup")
    _prev["backups"] = newest
    STATE.set("slow", "nas_backups", res)


def clawhost_etc():
    """Planifications et montages de clawhost lus dans sa dernière sauvegarde /etc (sur le NAS)."""
    safe = "[A-Za-z0-9._@-]+"   # noms acceptés dans l'archive : rien qui puisse être découpé ou pris pour une option
    cmd = (f"d=; for x in /mnt/user/backups/{CLAW_GLOB}; do [ -d \"$x\" ] && d=$x; done; [ -f \"$d/etc.tgz\" ] || exit 0; "
           "echo \"@@dir\"; echo \"$d\"; "
           f"for f in $(tar -tzf \"$d/etc.tgz\" 2>/dev/null | grep -E '^etc/(crontab|cron\\.d/{safe}|systemd/system/{safe}\\.timer|fstab)$'); do "
           "echo \"@@file $f\"; tar -xzOf \"$d/etc.tgz\" -- \"$f\" 2>/dev/null | grep -vE '^\\s*(#|$)'; done; "
           f"for f in $(tar -tzf \"$d/etc.tgz\" 2>/dev/null | grep -E '^etc/systemd/system/{safe}\\.timer$'); do s=${{f%.timer}}.service; "
           "echo \"@@file $s\"; tar -xzOf \"$d/etc.tgz\" -- \"$s\" 2>/dev/null | grep -E '^(Description|ExecStart)='; done; "
           "echo @@crondaily; tar -tzf \"$d/etc.tgz\" 2>/dev/null | grep -E '^etc/cron\\.(daily|weekly|monthly|hourly)/.+' ")
    out = SSHC.run(cmd, timeout=40)
    if not out:
        return
    files, cur, rp = {}, None, []
    for line in out.splitlines():
        if line.startswith("@@file "):
            cur = line[7:].strip()
            files[cur] = []
        elif line.startswith("@@crondaily"):
            cur = "__rp"
        elif line.startswith("@@dir"):
            cur = "__dir"
        elif cur == "__rp":
            rp.append(line.strip())
        elif cur == "__dir":
            files["__dir"] = line.strip()
        elif cur:
            files[cur].append(redact(line))
    timers = []
    for f, lines in files.items():
        if f.endswith(".timer"):
            svc = files.get(f[:-6] + ".service", [])
            d = {"unit": f.split("/")[-1], "lines": lines,
                 "desc": next((l.split("=", 1)[1] for l in svc if l.startswith("Description=")), ""),
                 "exec": next((l.split("=", 1)[1] for l in svc if l.startswith("ExecStart=")), ""),
                 "calendar": next((l.split("=", 1)[1] for l in lines if l.startswith("OnCalendar=")), "")}
            timers.append(d)
    mounts = []
    for line in files.get("etc/fstab", []):
        p = line.split()
        if len(p) >= 3:
            mounts.append({"source": p[0], "target": p[1], "fstype": p[2],
                           "options": ",".join(o for o in p[3].split(",") if not o.startswith("credentials")) if len(p) > 3 else ""})
    crons = []
    for f, lines in files.items():
        if f == "etc/crontab" or f.startswith("etc/cron.d/"):
            for line in lines:
                p = line.split()
                if len(p) >= 7 and not re.match(r"^[A-Z_]+=", line):
                    crons.append({"schedule": " ".join(p[:5]), "user": p[5], "command": " ".join(p[6:]), "source": f})
    STATE.set("slow", "claw_etc", {"timers": timers, "mounts": mounts, "crons": crons, "run_parts": rp,
                                   "from_backup": files.get("__dir", ""), "t": time.time()})
