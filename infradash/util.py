"""Outils communs : masquage des secrets, calcul de débits, parseur cron, petites aides."""
import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Europe/Paris")

# --- Masquage des secrets ----------------------------------------------------
_SECRET_PATTERNS = [
    (re.compile(r"(?i)((?:pass(?:word)?|pwd|token|secret|api[_-]?key|apikey|key|credentials|auth)\s*[=:]\s*[\"']?)[^\s\"'&,;]+"), r"\1•••"),
    (re.compile(r"(?i)(https?://[^/\s:@]+:)[^@\s]+@"), r"\1•••@"),
    (re.compile(r"(/api/push/)[A-Za-z0-9]+"), r"\1•••"),
    (re.compile(r"(hc-ping\.com/)[A-Za-z0-9-]+"), r"\1•••"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._-]+"), r"\1•••"),
    (re.compile(r"(?i)(\s--password[= ])\S+"), r"\1•••"),
]


def redact(text):
    if not text:
        return text
    for rx, rep in _SECRET_PATTERNS:
        text = rx.sub(rep, text)
    return text


# --- Exécution de commandes ---------------------------------------------------
def run(cmd, timeout=10, shell=False):
    """Lance une commande en lecture seule, renvoie stdout ('' en cas d'échec)."""
    try:
        p = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ""


# --- Débits -------------------------------------------------------------------
class RateTracker:
    """Transforme des compteurs cumulés en débits (unité/s)."""

    def __init__(self):
        self.prev = {}
        self.lock = threading.Lock()

    def rate(self, key, value, now=None):
        now = now or time.time()
        with self.lock:
            p = self.prev.get(key)
            self.prev[key] = (value, now)
        if not p:
            return 0.0
        dv, dt = value - p[0], now - p[1]
        if dt <= 0 or dv < 0:      # compteur remis à zéro (redémarrage)
            return 0.0
        return dv / dt


class Ring:
    """Historique court en mémoire pour les graphes temps réel."""

    def __init__(self, size=900):
        self.d = deque(maxlen=size)
        self.lock = threading.Lock()

    def add(self, t, v):
        with self.lock:
            self.d.append((round(t, 1), v))

    def list(self):
        with self.lock:
            return list(self.d)


# --- Parseur cron ---------------------------------------------------------------
_ALIASES = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}
_DOW_NAMES = {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
_MON_NAMES = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}


def _field(spec, lo, hi, names=None):
    vals = set()
    for part in spec.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
        if part in ("*", ""):
            a, b = lo, hi
        elif "-" in part:
            a, b = part.split("-", 1)
            a = names.get(a.lower(), a) if names else a
            b = names.get(b.lower(), b) if names else b
            a, b = int(a), int(b)
        else:
            a = int(names.get(part.lower(), part) if names else part)
            b = hi if step > 1 else a
        vals.update(range(a, b + 1, step))
    return vals


class Cron:
    def __init__(self, expr):
        expr = _ALIASES.get(expr.strip(), expr.strip())
        self.expr = expr
        f = expr.split()
        if len(f) != 5:
            raise ValueError(expr)
        self.minute = _field(f[0], 0, 59)
        self.hour = _field(f[1], 0, 23)
        self.dom = _field(f[2], 1, 31)
        self.month = _field(f[3], 1, 12, _MON_NAMES)
        dow = _field(f[4], 0, 7, _DOW_NAMES)
        self.dow = {d % 7 for d in dow}
        self.dom_any = f[2] == "*"
        self.dow_any = f[4] == "*"

    def _day_ok(self, d):
        if d.month not in self.month:
            return False
        dom_ok = d.day in self.dom
        dow_ok = (d.isoweekday() % 7) in self.dow
        if self.dom_any and self.dow_any:
            return True
        if self.dom_any:
            return dow_ok
        if self.dow_any:
            return dom_ok
        return dom_ok or dow_ok   # règle cron : OU logique si les deux sont restreints

    def runs_between(self, start, end, limit=400):
        """Occurrences dans [start, end) (datetimes avec fuseau)."""
        out = []
        day = start.replace(hour=0, minute=0, second=0, microsecond=0)
        hours, minutes = sorted(self.hour), sorted(self.minute)
        while day < end and len(out) < limit:
            if self._day_ok(day):
                for h in hours:
                    for m in minutes:
                        t = day.replace(hour=h, minute=m)
                        if start <= t < end:
                            out.append(t)
                            if len(out) >= limit:
                                return out
            day = (day + timedelta(days=1)).replace(hour=0, minute=0)
        return out

    def next_run(self, after=None):
        after = after or datetime.now(TZ)
        r = self.runs_between(after + timedelta(seconds=1), after + timedelta(days=400), limit=1)
        return r[0] if r else None

    def prev_run(self, before=None):
        before = before or datetime.now(TZ)
        for days in (2, 9, 40, 400):
            r = self.runs_between(before - timedelta(days=days), before, limit=100000)
            if r:
                return r[-1]
        return None

    def per_day(self):
        n = len(self.hour) * len(self.minute)
        if self.dom_any and self.dow_any:
            return n
        return n * (len(self.dow) / 7 if not self.dow_any else len(self.dom) / 30)


_JOURS = ["dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"]


def cron_human(expr):
    """Traduction française lisible d'une expression cron."""
    e = _ALIASES.get(expr.strip(), expr.strip())
    if expr.strip() == "@reboot":
        return "au démarrage"
    f = e.split()
    if len(f) != 5:
        return expr
    mi, h, dom, mon, dow = f
    try:
        if mi.startswith("*/") and h == "*" and dom == mon == dow == "*":
            return f"toutes les {mi[2:]} min"
        if mi == "*" and h == "*":
            return "chaque minute"
        if h == "*" and mi.isdigit():
            return f"chaque heure à :{int(mi):02d}"
        if mi.startswith("*/") and "-" in h:
            a, b = h.split("-")
            base = f"toutes les {mi[2:]} min de {a}h à {b}h"
        elif mi.isdigit() and h.startswith("*/"):
            base = f"toutes les {h[2:]} h (à :{int(mi):02d})"
        elif mi.isdigit() and all(x.isdigit() for x in h.split(",")):
            hs = [f"{int(x):02d}:{int(mi):02d}" for x in h.split(",")]
            base = " et ".join(hs) if len(hs) <= 2 else ", ".join(hs[:-1]) + " et " + hs[-1]
        else:
            base = e
        if dom == "*" and dow == "*":
            return ("tous les jours à " if ":" in base and not base.startswith("toutes") else "") + base
        if dom == "*" and dow != "*":
            ds = sorted(_field(dow, 0, 7, _DOW_NAMES))
            if ds == [1, 2, 3, 4, 5]:
                return f"du lundi au vendredi à {base}"
            return "le " + ", ".join(_JOURS[d % 7] for d in ds) + f" à {base}"
        if dom != "*" and dow == "*":
            return f"le {dom} du mois à {base}"
    except Exception:
        pass
    return e


def fmt_dt(d):
    return d.isoformat() if d else None


def now_ts():
    return time.time()


def is_private(ip):
    return (ip.startswith(("10.", "192.168.", "127.", "169.254.", "fe80", "::1", "fd"))
            or bool(re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)))


def is_tailscale(ip):
    if ip.startswith("fd7a:115c:a1e0"):
        return True
    m = re.match(r"100\.(\d+)\.", ip)
    return bool(m and 64 <= int(m.group(1)) <= 127)
