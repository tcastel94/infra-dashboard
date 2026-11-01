#!/usr/bin/env python3
"""InfraDash — dashboard temps réel du homelab, du NAS et de clawhost.

Lecture seule : aucune action n'est effectuée sur les machines surveillées.
"""
import hashlib
import ipaddress
import json
import mimetypes
import os
import signal
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from infradash import (actions, ai, alerts, architect, claw, egress, forecast, homelab, lan, model, nas, netscan, network, ports, remedy,  # noqa: E402
                       scores, vm, vulns)
from infradash.config import ALLOWED_NETS, LISTEN_HOST, LISTEN_PORT, STATIC_DIR  # noqa: E402
from infradash.runner import loop  # noqa: E402
from infradash.state import STATE  # noqa: E402

NETS = [ipaddress.ip_network(n) for n in ALLOWED_NETS]
TRUSTED_HOSTNAMES = {"localhost", "homelab-netnode", "homelab-netnode.local"} | {
    h.strip().lower() for h in os.environ.get("INFRADASH_HOSTNAMES", "").split(",") if h.strip()}
STARTED = time.time()
VULNS_MIN_GAP = 1.0        # un client qui redemande /api/vulns moins d'1 s après la réponse précédente (boucle) est freiné
_VULNS_SENT = {}           # IP -> instant du dernier envoi de /api/vulns
_VULNS_JSON = [None, b""]  # (clé, réponse sérialisée) : ~135 Ko, sérialisés une fois par version de l'état


def _build_id():
    """Empreinte des fichiers de l'interface : un navigateur ouvert se recharge après un déploiement."""
    h = hashlib.sha1()
    for root, dirs, files in os.walk(STATIC_DIR):
        dirs[:] = sorted(d for d in dirs if d != "vendor")
        for f in sorted(files):
            if not f.startswith("_"):   # pages de test temporaires exclues
                st = os.stat(os.path.join(root, f))
                h.update(f"{root}/{f}:{st.st_size}:{int(st.st_mtime)}".encode())
    return h.hexdigest()[:12]


BUILD = _build_id()


def _vulns_body():
    v = STATE.get("slow", "vulns") or {}
    key = (id(v), v.get("generated_at"), v.get("inventory_at"))
    if _VULNS_JSON[0] != key:
        _VULNS_JSON[:] = [key, json.dumps(v, default=str, ensure_ascii=False).encode()]
    return _VULNS_JSON[1]


def derived_fast():
    STATE.set("derived", "topology", model.build_topology())


def derived_slow():
    STATE.set("derived", "jobs", model.build_jobs())
    if STATE.get("slow", "nas_backups") is not None:   # pas de faux « sauvegarde absente » avant le premier inventaire
        STATE.set("derived", "backups", model.build_backups())
    STATE.set("derived", "insights", model.build_insights())


def start_collectors():
    loop("homelab.fast", 2, homelab.fast)
    loop("homelab.containers", 5, homelab.containers)
    loop("homelab.slow", 60, homelab.slow)
    loop("homelab.dns", 30, homelab.dns_check)
    loop("homelab.apt", 6 * 3600, homelab.apt_check, initial_delay=90)
    loop("nas.slow", 60, nas.slow)
    loop("nas.fast", 3, nas.fast, initial_delay=1)
    loop("nas.conntrack", 10, nas.conntrack, initial_delay=4)
    loop("nas.sched", 300, nas.very_slow, initial_delay=2)
    loop("nas.backups", 1200, nas.backups, initial_delay=6)
    loop("nas.claw_etc", 3600, nas.clawhost_etc, initial_delay=12)
    loop("clawhost.probes", 10, claw.probes, initial_delay=1)
    loop("clawhost.inventory", 1800, claw.inventory, initial_delay=30)
    loop("net.tailscale", 5, network.tailscale)
    loop("net.lan", 60, network.neighbors)
    loop("net.latency", 10, network.latency, initial_delay=2)
    loop("net.public", 300, network.public_endpoints, initial_delay=25)
    loop("net.wan", 1800, network.wan_ip, initial_delay=8)
    loop("net.homepage", 300, network.homepage_links, initial_delay=10)
    loop("net.speedtest", 600, network.speedtest, initial_delay=3)
    loop("derived.fast", 3, derived_fast, initial_delay=5)
    loop("derived.slow", 30, derived_slow, initial_delay=15)
    loop("vulns", 600, vulns.run, initial_delay=40)
    loop("netscan", 60, netscan.run, initial_delay=15)
    loop("actions", 30, actions.publish, initial_delay=8)
    loop("forecast", 600, forecast.run, initial_delay=50)
    loop("egress", 30, egress.run, initial_delay=20)
    loop("lan.discover", 300, lan.auto, initial_delay=25)
    loop("lan.publish", 15, lan.publish, initial_delay=12)
    loop("ports", 120, ports.run, initial_delay=18)
    loop("architect", 120, architect.refresh, initial_delay=60)
    loop("scores", 60, scores.run, initial_delay=60)
    loop("alerts", 30, alerts.run, initial_delay=70)
    if not os.environ.get("INFRADASH_STAGING"):  # une instance de test n'écrit pas dans VictoriaMetrics et ne sollicite pas le GPU
        loop("vm.push", 15, vm.push, initial_delay=30)
        loop("ai", 60, ai.maybe_run, initial_delay=180)


LIVE_NEVER = ("nas_conntrack",)                       # données internes, inutiles au navigateur
LIVE_SLOWER = ("nas_containers", "homelab_containers")  # envoyées une fois sur trois (toutes les 6 s)


def payload(full, tick=0):
    snap = STATE.snapshot()
    out = {"t": time.time(), "live": snap.get("live", {}), "topology": snap.get("derived", {}).get("topology"), "build": BUILD}
    for k in list(out["live"]):
        if k.startswith("_") or k in LIVE_NEVER or (k in LIVE_SLOWER and not full and tick % 3):
            del out["live"][k]
    if full:
        v = snap.get("slow", {}).get("vulns")
        if isinstance(v, dict):   # le détail complet passe par /api/vulns
            snap["slow"]["vulns"] = {k: x for k, x in v.items() if k not in ("inventory", "findings", "nofix_distro", "dismissed")}
            snap["slow"]["vulns"]["actions"] = [{k: x for k, x in a.items() if k not in ("findings", "component_ids")}
                                                for a in v.get("actions") or []]
            snap["slow"]["vulns"]["n_inventory"] = len(v.get("inventory") or [])
            snap["slow"]["vulns"]["n_findings"] = (v.get("stats") or {}).get("findings") or len(v.get("findings") or [])
        pt = snap.get("slow", {}).get("ports")
        if isinstance(pt, dict):   # la liste complète des ports passe par /api/ports
            snap["slow"]["ports"] = {"t": pt.get("t"), "hosts": {k: dict({a: b for a, b in v.items() if a not in ("ports", "free")}, n_ports=len(v.get("ports") or []))
                                                                for k, v in (pt.get("hosts") or {}).items()}}
        ns = snap.get("slow", {}).get("netscan")
        if isinstance(ns, dict):   # le navigateur n'a besoin que de la synthèse (constats bruts et appareils : lan_devices)
            snap["slow"]["netscan"] = {k: x for k, x in ns.items() if k not in ("findings", "devices", "top_bw", "top_risk")}
        out.update({"slow": snap.get("slow", {}), "derived": snap.get("derived", {}), "events": STATE.recent_events(),
                    "collectors": dict(STATE.collector_status), "uptime": time.time() - STARTED})
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "InfraDash/2.0"
    timeout = 60   # une connexion lente ne monopolise pas un fil indéfiniment (s'applique à chaque envoi, pas à la durée du flux)

    def log_message(self, fmt, *args):  # journal discret
        if "/api/stream" not in (args[0] if args else ""):
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _host_ok(self):
        """Anti « DNS rebinding » : l'en-tête Host doit être une IP ou un nom connu (sinon un site tiers pourrait lire l'API)."""
        h = self.headers.get("Host")
        if not h:
            return True
        name = (urlparse("//" + h).hostname or "").lower()
        try:
            ipaddress.ip_address(name)
            return True
        except ValueError:
            return name in TRUSTED_HOSTNAMES or (name.startswith("homelab-netnode.") and name.endswith(".ts.net"))

    def _allowed(self):
        try:
            ip = ipaddress.ip_address(self.client_address[0].replace("::ffff:", ""))
        except ValueError:
            return False
        return any(ip in n for n in NETS)

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._allowed() or not self._host_ok():
            return self._send(403, '{"error":"forbidden"}')
        u = urlparse(self.path)
        p = u.path
        try:
            if p == "/api/state":
                return self._send(200, json.dumps(payload(True), default=str, ensure_ascii=False), extra={"Cache-Control": "no-store"})
            if p == "/api/stream":
                return self._stream()
            if p == "/api/history":
                q = parse_qs(u.query)
                res = vm.history(q.get("key", [""])[0], q.get("host", [""])[0], q.get("range", ["24h"])[0])
                return self._send(200, json.dumps(res), extra={"Cache-Control": "no-store"})
            if p == "/api/vulns":
                ip = self.client_address[0]
                if time.time() - _VULNS_SENT.get(ip, 0) < VULNS_MIN_GAP:
                    time.sleep(2)   # frein : un onglet qui boucle (ancien code en mémoire) passe à ~0,5 requête/s
                self._send(200, _vulns_body(), extra={"Cache-Control": "no-store"})
                _VULNS_SENT[ip] = time.time()
                return
            if p == "/api/egress":
                return self._send(200, json.dumps(STATE.get("slow", "egress") or {}, default=str, ensure_ascii=False),
                                  extra={"Cache-Control": "no-store"})
            if p == "/api/vulns/refresh":
                return self._send(200, json.dumps(vulns.refresh_status(), default=str, ensure_ascii=False),
                                  extra={"Cache-Control": "no-store"})
            if p == "/api/lan/scan":
                return self._send(200, json.dumps(STATE.get("slow", "lan_scan") or {}, default=str, ensure_ascii=False), extra={"Cache-Control": "no-store"})
            if p == "/api/lan/inventory":
                return self._send(200, json.dumps(STATE.get("slow", "lan_inventory") or {}, default=str, ensure_ascii=False), extra={"Cache-Control": "no-store"})
            if p == "/api/ports":
                return self._send(200, json.dumps(STATE.get("slow", "ports") or {}, default=str, ensure_ascii=False), extra={"Cache-Control": "no-store"})
            if p == "/api/ports/free":
                q = parse_qs(u.query)
                try:
                    res = ports.free_ports(q.get("host", [""])[0], int(q.get("from", ["1024"])[0]), int(q.get("to", ["65535"])[0]), int(q.get("n", ["20"])[0]))
                except ValueError:
                    res = {"error": "paramètres invalides"}
                return self._send(200, json.dumps(res), extra={"Cache-Control": "no-store"})
            if p == "/api/remedy/catalog":
                return self._send(200, json.dumps(remedy.catalog(), default=str, ensure_ascii=False), extra={"Cache-Control": "no-store"})
            if p == "/api/remedy/status":
                return self._send(200, json.dumps(remedy.status(), default=str, ensure_ascii=False), extra={"Cache-Control": "no-store"})
            if p == "/api/health":
                return self._send(200, json.dumps({"ok": True, "uptime": time.time() - STARTED}))
            if p in ("/", "/index.html"):
                p = "/index.html"
            path = os.path.realpath(os.path.join(STATIC_DIR, p.lstrip("/")))
            if not path.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(path):
                return self._send(404, '{"error":"not found"}')
            ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            with open(path, "rb") as f:
                cache = "no-cache" if path.endswith((".html", ".js", ".css")) and "vendor" not in path else "max-age=86400"
                return self._send(200, f.read(), ctype, {"Cache-Control": cache})
        except BrokenPipeError:
            pass
        except Exception as e:  # noqa
            try:
                self._send(500, json.dumps({"error": str(e)}))
            except Exception:
                pass

    def do_POST(self):
        """Actions possibles : analyses IA locale (diagnostic, question, architecte), revérification des vulnérabilités, acquittement
        d'alertes, réglages des notifications, scan du réseau local et fiche des appareils (nom, icône…), les actions du catalogue
        infradash/actions.py (diagnostics en lecture seule, pause / reprise de la parité) et — désactivé par défaut, phrase secrète
        obligatoire — l'exécution des commandes du plan de correction après validation par infradash/remedy.py (aucune commande
        n'est jamais lue dans la requête : seulement un identifiant d'action, un numéro et l'empreinte du plan affiché)."""
        if not self._allowed() or not self._host_ok():
            return self._send(403, '{"error":"forbidden"}')
        # Protection CSRF : en-tête personnalisé obligatoire (impossible à poser depuis un autre site sans pré-vol CORS)
        origin = self.headers.get("Origin")
        if self.headers.get("X-InfraDash") != "1" or (origin and urlparse(origin).netloc != self.headers.get("Host")):
            return self._send(403, '{"error":"en-tête manquant"}')
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > 4096:
                return self._send(413, '{"error":"corps invalide ou trop volumineux"}')
            body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            p = urlparse(self.path).path
            if p == "/api/ai/run":
                return self._send(200, json.dumps(ai.request_run(), default=str, ensure_ascii=False))
            if p == "/api/ai/ask" and hasattr(ai, "ask"):
                q = str(body.get("question", ""))[:500].strip()
                if not q:
                    return self._send(400, '{"error":"question vide"}')
                return self._send(200, json.dumps(ai.ask(q), default=str, ensure_ascii=False))
            if p == "/api/vulns/refresh":
                focus = body.get("focus")
                return self._send(200, json.dumps(vulns.request_refresh(str(focus)[:200] if focus else None),
                                                  default=str, ensure_ascii=False))
            if p == "/api/actions/run":   # action du catalogue (identifiant seul), confirmée dans l'interface
                return self._send(200, json.dumps(actions.run(str(body.get("id") or "")[:40]), default=str, ensure_ascii=False))
            if p == "/api/lan/scan":
                return self._send(200, json.dumps(lan.request_scan(bool(body.get("deep", True))), default=str, ensure_ascii=False))
            if p == "/api/lan/device":
                fields = {k: body[k] for k in ("name", "icon", "cat", "note", "trusted", "conn") if k in body}
                return self._send(200, json.dumps(lan.set_meta(body.get("mac"), fields), default=str, ensure_ascii=False))
            if p == "/api/architect/run":
                return self._send(200, json.dumps(architect.request_run(), default=str, ensure_ascii=False))
            if p == "/api/remedy/plan":
                return self._send(200, json.dumps(remedy.plan(str(body.get("action") or "")[:200], body.get("index"), self.client_address[0]),
                                                  default=str, ensure_ascii=False))
            if p == "/api/remedy/run":
                return self._send(200, json.dumps(remedy.execute(str(body.get("plan_id") or "")[:20], str(body.get("fingerprint") or "")[:40],
                                                                 body.get("pin"), self.client_address[0]), default=str, ensure_ascii=False))
            if p == "/api/alerts/ack":
                if body.get("all"):
                    alerts.ack_all(body.get("level"))
                elif body.get("key"):
                    (alerts.unack if body.get("undo") else alerts.ack)(str(body["key"])[:200])
                return self._send(200, json.dumps(STATE.get("derived", "alerts") or {}, default=str, ensure_ascii=False))
            if p == "/api/settings":
                allowed = {k: bool(v) for k, v in body.items() if k in ("notify_unraid", "notify_warn")}
                if allowed:
                    alerts.set_settings(allowed)
                return self._send(200, json.dumps(alerts.get_settings(), default=str))
            return self._send(404, '{"error":"not found"}')
        except Exception as e:  # noqa
            return self._send(500, json.dumps({"error": str(e)}))

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        n = 0
        try:
            while True:
                full = n % 10 == 0
                data = json.dumps(payload(full, n), default=str, ensure_ascii=False)
                self.wfile.write(f"event: {'full' if full else 'live'}\ndata: {data}\n\n".encode())
                self.wfile.flush()
                n += 1
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


def main():
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("image/svg+xml", ".svg")
    start_collectors()
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    srv.daemon_threads = True
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    print(f"InfraDash en écoute sur http://{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
