"""VictoriaMetrics : envoi des métriques du NAS/clawhost (écriture additive) et lecture de l'historique."""
import json
import re
import time
import urllib.parse
import urllib.request

from .config import VM_URL
from .state import STATE

_LBL = re.compile(r"[^a-zA-Z0-9_.:/ -]")


def _l(v):
    return _LBL.sub("_", str(v))[:80]


def push():
    lines = []

    def g(metric, value, **labels):
        if value is None:
            return
        try:
            v = float(value)
        except (TypeError, ValueError):
            return
        lb = ",".join(f'{k}="{_l(x)}"' for k, x in labels.items())
        lines.append(f"infradash_{metric}{{{lb}}} {v}")

    for host in ("nas", "homelab"):
        m = STATE.get("live", host) or {}
        if not m or m.get("down"):
            g("host_up", 0, host=host)
            continue
        g("host_up", 1, host=host)
        g("cpu_percent", m.get("cpu"), host=host)
        g("iowait_percent", m.get("iowait"), host=host)
        g("mem_percent", m.get("mem"), host=host)
        g("load1", (m.get("load") or [None])[0], host=host)
        g("net_rx_bytes", m.get("rx"), host=host)
        g("net_tx_bytes", m.get("tx"), host=host)
        g("disk_read_bytes", m.get("dread"), host=host)
        g("disk_write_bytes", m.get("dwrite"), host=host)
    nas = STATE.get("live", "nas") or {}
    arr = nas.get("array") or {}
    try:
        if int(arr.get("mdResyncPos", 0)):
            g("parity_progress_percent", 100 * int(arr["mdResyncPos"]) / int(arr.get("mdResyncSize") or arr.get("mdResync")), host="nas")
        else:
            g("parity_progress_percent", 0, host="nas")
    except (ValueError, ZeroDivisionError):
        pass
    slow = STATE.get("slow", "nas") or {}
    for name, d in (slow.get("disks") or {}).items():
        if str(d.get("temp", "")).isdigit():
            g("disk_temp_celsius", d["temp"], host="nas", disk=name)
        if d.get("fsSize") and d.get("fsFree"):
            try:
                g("disk_used_percent", 100 * (1 - int(d["fsFree"]) / int(d["fsSize"])), host="nas", disk=name)
            except (ValueError, ZeroDivisionError):
                pass
    gpu = slow.get("gpu") or {}
    g("gpu_temp_celsius", gpu.get("temp"), host="nas")
    g("gpu_util_percent", gpu.get("util"), host="nas")
    g("gpu_power_watts", gpu.get("power"), host="nas")
    ups = slow.get("ups") or {}
    for k, n in (("BCHARGE", "ups_charge_percent"), ("LOADPCT", "ups_load_percent"), ("TIMELEFT", "ups_runtime_minutes")):
        if ups.get(k):
            g(n, ups[k].split()[0], host="nas")
    for c in STATE.get("live", "nas_containers") or []:
        if c["state"] != "running":
            continue
        g("container_cpu_percent", c["cpu"], host="nas", container=c["name"])
        g("container_mem_bytes", c["mem"], host="nas", container=c["name"])
        g("container_net_bytes", c["rx"] + c["tx"], host="nas", container=c["name"])
    claw = STATE.get("live", "clawhost") or {}
    if claw:
        g("host_up", 1 if claw.get("up") else 0, host="clawhost")
        g("ping_ms", claw.get("ping"), host="clawhost")
        for p in claw.get("probes", []):
            g("probe_up", 1 if p["up"] else 0, host="clawhost", port=p["port"], probe=p["name"])
            g("probe_ms", p.get("ms"), host="clawhost", port=p["port"], probe=p["name"])
    for k, v in (STATE.get("live", "latency") or {}).items():
        g("ping_ms", v.get("ms"), host=k)
    dns = STATE.get("live", "dns") or {}
    g("dns_ms", dns.get("ms") if dns.get("ok") else None, host="homelab")
    for e in (STATE.get("slow", "public") or {}).get("endpoints", []):
        g("public_up", 1 if e["ok"] else 0, domain=e["domain"])
        g("public_ms", e.get("ms"), domain=e["domain"])
    der = STATE.get("derived", "backups") or {}
    for c in der.get("chains", []):
        g("backup_age_hours", c.get("age_h"), chain=c["id"])
        g("backup_last_size_bytes", c.get("last_size"), chain=c["id"])
    for e in (STATE.get("derived", "topology") or {}).get("edges", []):
        g("flow_bytes", e["ab"] + e["ba"], src=e["from"], dst=e["to"], proto=e["proto"])
    if not lines:
        return
    req = urllib.request.Request(f"{VM_URL}/api/v1/import/prometheus", data=("\n".join(lines) + "\n").encode(), method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        r.read()


# Requêtes d'historique autorisées (aucune requête libre depuis le navigateur)
HOMELAB_Q = {
    "cpu": '100 - avg(rate(node_cpu_seconds_total{mode="idle",job="node-exporter"}[2m]))*100',
    "mem": '100*(1 - node_memory_MemAvailable_bytes{job="node-exporter"}/node_memory_MemTotal_bytes{job="node-exporter"})',
    "rx": 'sum(rate(container_network_receive_bytes_total{id="/",interface="enp0s25"}[2m]))',
    "tx": 'sum(rate(container_network_transmit_bytes_total{id="/",interface="enp0s25"}[2m]))',
    "load": 'node_load1{job="node-exporter"}',
    "temp": 'max(node_hwmon_temp_celsius{chip=~".*coretemp.*"})',
}
QUERIES = {
    "speed_dl": "speedtest_download_bits_per_second/1e6",
    "speed_ul": "speedtest_upload_bits_per_second/1e6",
    "speed_ping": "speedtest_ping_latency_milliseconds",
    "dns": 'infradash_dns_ms',
    "ping": 'infradash_ping_ms',
    "disk_temp": 'infradash_disk_temp_celsius',
    "parity": 'infradash_parity_progress_percent',
    "backup_age": 'infradash_backup_age_hours',
    "nas_top_cpu": 'topk(8, avg_over_time(infradash_container_cpu_percent{host="nas"}[5m]))',
    "homelab_containers_cpu": 'sum by (name) (rate(container_cpu_usage_seconds_total{name!=""}[2m]))*100',
    "flows": 'infradash_flow_bytes',
}


def history(key, host, rng):
    rngs = {"1h": (3600, 15), "6h": (6 * 3600, 60), "24h": (86400, 300), "7d": (7 * 86400, 1800), "30d": (30 * 86400, 7200)}
    span, step = rngs.get(rng, rngs["24h"])
    if host == "homelab" and key in HOMELAB_Q:
        q = HOMELAB_Q[key]
    elif host in ("nas", "clawhost", "homelab") and key in ("cpu", "mem", "rx", "tx", "load", "iowait"):
        q = {"cpu": "cpu_percent", "mem": "mem_percent", "rx": "net_rx_bytes", "tx": "net_tx_bytes", "load": "load1",
             "iowait": "iowait_percent"}[key]
        q = f'avg_over_time(infradash_{q}{{host="{host}"}}[{max(step, 30)}s])'
    elif key in QUERIES:
        q = QUERIES[key]
    else:
        return {"error": "requête inconnue"}
    now = time.time()
    url = f"{VM_URL}/api/v1/query_range?" + urllib.parse.urlencode({"query": q, "start": now - span, "end": now, "step": f"{step}s"})
    with urllib.request.urlopen(url, timeout=10) as r:
        data = json.loads(r.read()).get("data", {}).get("result", [])
    return {"series": [{"labels": d["metric"], "values": [[float(t), float(v)] for t, v in d["values"]]} for d in data],
            "step": step, "range": rng}
