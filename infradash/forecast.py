"""Prévisions déterministes : régressions robustes (Theil-Sen) et échéances calculées.

Sources : VictoriaMetrics (historique long), état courant (STATE) et un petit historique local
(DATA_DIR/forecast-hist.json) pour ce qui n'est pas encore dans VictoriaMetrics (cache NVMe, docker.img).
Aucune prévision n'est inventée : sans assez de points, la confiance reste « faible » et le détail le dit.
"""
import json
import math
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from .config import DATA_DIR, VM_URL
from .state import STATE
from .util import TZ, Cron

HIST_FILE = os.path.join(DATA_DIR, "forecast-hist.json")
EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")
DAY = 86400.0
_LOCK = threading.Lock()
_HIST = {"loaded": False, "points": []}
SEV_ORDER = {"crit": 0, "warn": 1, "info": 2}


# --------------------------------------------------------------------------- VictoriaMetrics
def _vm(path, params, timeout=8):
    url = f"{VM_URL}{path}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        d = json.loads(r.read())
    if d.get("status") != "success":
        raise RuntimeError(d.get("error", "réponse VictoriaMetrics invalide"))
    return d["data"]["result"]


def vm_range(query, span_s, step_s, end=None):
    """[(labels, [(ts, valeur), ...]), ...] ; valeurs non finies ignorées."""
    end = end or time.time()
    out = []
    for s in _vm("/api/v1/query_range", {"query": query, "start": end - span_s, "end": end, "step": f"{int(step_s)}s"}):
        pts = []
        for t, v in s.get("values", []):
            try:
                f = float(v)
            except (TypeError, ValueError):
                continue
            if math.isfinite(f):
                pts.append((float(t), f))
        out.append((s.get("metric", {}), pts))
    return out


# --------------------------------------------------------------------------- statistiques
def _median(xs):
    s = sorted(xs)
    n = len(s)
    if not n:
        return None
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def fit(points):
    """Régression de Theil-Sen (médiane des pentes, insensible aux valeurs aberrantes) sur [(ts, v)].

    Renvoie pente/jour, ordonnée au dernier point, R², écart-type des résidus, nb de points, durée couverte (j)
    et `flat` (dérive sur 30 j inférieure au bruit), ou None si moins de 3 points exploitables."""
    pts = sorted((t, v) for t, v in points if v is not None and math.isfinite(v))
    if len(pts) < 3:
        return None
    t0 = pts[-1][0]
    xs = [(t - t0) / DAY for t, _ in pts]
    ys = [v for _, v in pts]
    idx = list(range(len(pts)))
    if len(idx) > 150:  # sous-échantillonnage régulier : 150 points = ~11 000 paires
        step = len(idx) / 150
        idx = sorted({int(i * step) for i in range(150)} | {len(idx) - 1})
    sx, sy = [xs[i] for i in idx], [ys[i] for i in idx]
    slopes = [(sy[j] - sy[i]) / (sx[j] - sx[i]) for i in range(len(sx)) for j in range(i + 1, len(sx)) if sx[j] != sx[i]]
    if not slopes:
        return None
    m = _median(slopes)
    b = _median([y - m * x for x, y in zip(xs, ys)])
    # R² et dispersion calculés sur les points « normaux » (résidu < 5 MAD) : quelques valeurs aberrantes ne ruinent pas la confiance
    res = [y - (m * x + b) for x, y in zip(xs, ys)]
    mad = _median([abs(r) for r in res]) or 0.0
    keep = [i for i, r in enumerate(res) if mad == 0 or abs(r) <= 5 * 1.4826 * mad] or list(range(len(ys)))
    ki = [ys[i] for i in keep]
    mean = sum(ki) / len(ki)
    sst = sum((y - mean) ** 2 for y in ki)
    ssr = sum(res[i] ** 2 for i in keep)
    r2 = max(0.0, 1 - ssr / sst) if sst > 1e-12 else (1.0 if ssr < 1e-12 else 0.0)
    sd = math.sqrt(ssr / max(1, len(keep) - 2))
    span = xs[-1] - xs[0]
    return {"slope": m, "b": b, "r2": r2, "sd": sd, "n": len(ys), "span": span, "t_last": t0, "v_last": ys[-1],
            "outliers": len(ys) - len(keep), "flat": abs(m) * 30 < max(2 * sd, 1e-9)}


def dejump(points, k=10.0, min_abs=0.0, direction=-1):
    """Neutralise les sauts ponctuels (nettoyage = baisse brutale) pour estimer le rythme « organique ».

    Un saut est une variation supérieure à k fois la variation médiane par unité de temps et à min_abs.
    La série est reconstruite à rebours : la dernière valeur réelle est conservée."""
    if len(points) < 4:
        return list(points), 0
    rates = []
    for (t1, v1), (t2, v2) in zip(points, points[1:]):
        if t2 > t1 and v2 != v1:
            rates.append(abs(v2 - v1) / (t2 - t1))
    if not rates:
        return list(points), 0
    med = _median(rates)
    out = [points[-1]]
    acc = points[-1][1]
    jumps = 0
    for i in range(len(points) - 2, -1, -1):
        (t1, v1), (t2, v2) = points[i], points[i + 1]
        d = v2 - v1
        if abs(d) > max(k * med * max(t2 - t1, 1), min_abs) and (direction is None or d * direction > 0):
            jumps += 1
            d = 0.0
        acc -= d
        out.append((t1, acc))
    out.reverse()
    return out, jumps


def _confidence(f, eta=None):
    if not f or f["n"] < 6 or f["span"] < 0.25:
        return "faible"
    if f["flat"]:
        lvl = 2 if f["span"] >= 7 and f["n"] >= 20 else 1 if f["span"] >= 2 else 0
    else:
        lvl = 2 if f["r2"] >= 0.8 and f["span"] >= 7 and f["n"] >= 20 else 1 if f["r2"] >= 0.5 and f["span"] >= 2 and f["n"] >= 10 else 0
    if eta is not None and eta > 3 * max(f["span"], 0.1):  # extrapolation loin au-delà de l'historique observé
        lvl -= 1
    return ("faible", "moyenne", "forte")[max(0, lvl)]


def _gate(f, eta, max_extrap=None):
    """Confiance + échéance : une tendance de confiance « faible » ne produit jamais de date (pas de prévision farfelue).

    max_extrap : pour les grandeurs non cumulatives (mémoire, températures, latence), pas d'échéance au-delà de
    max_extrap fois la durée d'historique observée."""
    conf = _confidence(f, eta)
    if eta is not None and max_extrap and eta > max_extrap * max(f["span"], 0.1):
        return None, conf
    return (None if conf == "faible" else eta), conf


def _sev_level(cur, warn, crit):
    return "crit" if cur is not None and cur >= crit else "warn" if cur is not None and cur >= warn else "info"


def _eta(f, current, threshold):
    """Jours avant d'atteindre `threshold` (série croissante), None si stable/décroissante ou déjà dépassé."""
    if not f or f["flat"] or current is None or f["slope"] <= 0 or current >= threshold:
        return None
    return (threshold - current) / f["slope"]


def _horizon(days):
    if days is None:
        return ">90j"
    return "24h" if days <= 1 else "7j" if days <= 7 else "30j" if days <= 30 else "90j" if days <= 90 else ">90j"


def _sev_eta(days, crit=7, warn=30):
    if days is None:
        return "info"
    return "crit" if days <= crit else "warn" if days <= warn else "info"


# --------------------------------------------------------------------------- formatage FR
def _fr(x, nd=1):
    return f"{x:,.{nd}f}".replace(",", " ").replace(".", ",")


def _fb(n):
    n = float(n or 0)
    for u, f in (("To", 1e12), ("Go", 1e9), ("Mo", 1e6), ("ko", 1e3)):
        if abs(n) >= f:
            return f"{_fr(n / f, 1)} {u}"
    return f"{int(n)} o"


def _fd(ts, hour=True):
    return datetime.fromtimestamp(ts, TZ).strftime("%d/%m/%Y %H:%M" if hour else "%d/%m/%Y")


def _fdur(days):
    if days is None:
        return "—"
    if days < 1:
        return f"{max(1, round(days * 24))} h"
    if days < 60:
        return f"{_fr(days, 1 if days < 10 else 0)} j"
    if days < 730:
        return f"{_fr(days / 30.4, 0)} mois"
    return f"{_fr(days / 365, 1)} ans"


def _r(x, nd=3):
    if x is None or not isinstance(x, (int, float)) or not math.isfinite(x):
        return None
    return round(x) if abs(x) >= 1000 else round(x, nd)


def _series(points, n=60, nd=2):
    """Réduit à ≤ n points (moyenne par tranche de temps) pour un mini-graphe ; dernier point réel conservé."""
    pts = sorted(points)
    if not pts:
        return []
    if len(pts) > n:
        t0, t1 = pts[0][0], pts[-1][0]
        w = (t1 - t0) / n or 1
        buckets = {}
        for t, v in pts:
            buckets.setdefault(min(n - 1, int((t - t0) / w)), []).append((t, v))
        red = [(b[-1][0], sum(v for _, v in b) / len(b)) for _, b in sorted(buckets.items())]
        red[-1] = pts[-1]
        pts = red
    return [[int(t), round(v, nd) if nd else round(v)] for t, v in pts]


def _item(iid, title, metric, current, unit, host, *, trend=None, eta_days=None, confidence="faible", severity="info",
          horizon=None, detail="", series=None, threshold=None, fit_=None, projection=None, **extra):
    now = time.time()
    if eta_days is not None and eta_days > 730:  # au-delà de 2 ans : on ne donne pas de date (extrapolation non crédible)
        eta_days = None
        horizon = horizon or ">90j"
    eta_ts = now + eta_days * DAY if eta_days is not None else None
    it = {"id": iid, "title": title, "metric": metric, "current": _r(current), "unit": unit,
          "trend_per_day": _r(trend, 4), "eta_days": round(eta_days, 2) if eta_days is not None else None,
          "eta_date": datetime.fromtimestamp(eta_ts, TZ).isoformat(timespec="minutes") if eta_ts else None,
          "eta_ts": round(eta_ts) if eta_ts else None,
          "confidence": confidence, "severity": severity, "horizon": horizon or _horizon(eta_days), "detail": detail,
          "series": series or [], "host": host, "threshold": threshold}
    if fit_:
        it["fit"] = {"n": fit_["n"], "span_days": round(fit_["span"], 2), "r2": round(fit_["r2"], 3)}
    if projection is None and fit_ and current is not None and not fit_["flat"]:
        end = eta_ts if eta_ts and eta_days <= 90 else now + 30 * DAY
        projection = [[int(now), _r(current)], [int(end), _r(current + fit_["slope"] * (end - now) / DAY)]]
    if projection:
        it["projection"] = projection
    it.update(extra)
    return it


# --------------------------------------------------------------------------- historique local
def _hist_load():
    if _HIST["loaded"]:
        return
    _HIST["loaded"] = True
    try:
        with open(HIST_FILE) as f:
            _HIST["points"] = json.load(f).get("points", [])
    except (OSError, ValueError):
        _HIST["points"] = []


def _hist_save():
    now = time.time()
    keep, seen_h = [], set()
    for p in _HIST["points"]:
        age = now - p["t"]
        if age > 90 * DAY:
            continue
        if age > 7 * DAY:  # au-delà de 7 j : un point par heure suffit
            h = int(p["t"] // 3600)
            if h in seen_h:
                continue
            seen_h.add(h)
        keep.append(p)
    _HIST["points"] = keep
    tmp = HIST_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"v": 1, "points": keep}, f, separators=(",", ":"))
        os.replace(tmp, HIST_FILE)
    except OSError:
        pass


def _sample_history():
    """Échantillon toutes les 10 min (appel de run()) : cache NVMe, docker.img, /boot et array du NAS."""
    _hist_load()
    sched = STATE.get("slow", "nas_sched") or {}
    nslow = STATE.get("slow", "nas") or {}
    p = {}
    for d in sched.get("df") or []:
        key = {"/var/lib/docker": "docker", "/mnt/cache": "cache_df", "/boot": "boot"}.get(d.get("target"))
        if key and d.get("size"):
            p[key] = [d["used"], d["size"]]
    disks = nslow.get("disks") or {}
    c = disks.get("cache") or {}
    try:  # même formule que infradash_disk_used_percent (1 - libre/taille), en octets
        p["cache"] = [(int(c["fsSize"]) - int(c["fsFree"])) * 1024, int(c["fsSize"]) * 1024]
    except (KeyError, TypeError, ValueError):
        pass
    used = size = 0
    for n, d in disks.items():
        if n.startswith("disk") and d.get("fsSize") and d.get("fsFree"):
            try:
                used += (int(d["fsSize"]) - int(d["fsFree"])) * 1024
                size += int(d["fsSize"]) * 1024
            except ValueError:
                pass
    if size:
        p["array"] = [used, size]
    if not p:
        return
    p["t"] = round(max(sched.get("t") or 0, nslow.get("t") or 0) or time.time())
    with _LOCK:
        if _HIST["points"] and _HIST["points"][-1]["t"] >= p["t"]:
            return  # pas de nouvelle mesure depuis le dernier échantillon
        _HIST["points"].append(p)
        _hist_save()


def _hist_series(key, pct=True):
    out = []
    for p in _HIST["points"]:
        v = p.get(key)
        if v and v[1]:
            out.append((float(p["t"]), 100 * v[0] / v[1] if pct else float(v[0])))
    return out


def _merge(*series_lists):
    """Fusionne plusieurs séries [(t, v)] en ignorant les doublons à moins de 60 s."""
    allp = sorted(p for s in series_lists for p in s)
    out = []
    for t, v in allp:
        if out and t - out[-1][0] < 60:
            continue
        out.append((t, v))
    return out


# --------------------------------------------------------------------------- prévisions : capacité
def fc_homelab_root():
    sel = '{job="node-exporter",mountpoint="/"}'
    av = vm_range(f"node_filesystem_avail_bytes{sel}", 30 * DAY, 3600)
    sz = vm_range(f"node_filesystem_size_bytes{sel}", 2 * 3600, 600)
    rf = (STATE.get("live", "homelab") or {}).get("root_fs") or {}
    size = rf.get("size") or (sz[0][1][-1][1] if sz and sz[0][1] else None)
    if not size:
        return None
    pts = [(t, 100 * (1 - a / size)) for t, a in (av[0][1] if av else [])]
    if rf.get("size"):  # mesure locale la plus récente
        pts.append((time.time(), 100 * (1 - rf["free"] / rf["size"])))
    pts = _merge(pts)
    cur = pts[-1][1]
    free = size * (1 - cur / 100)
    adj, jumps = dejump(pts, min_abs=0.5)
    f = fit(adj)
    thr = 95.0
    eta, conf = _gate(f, _eta(f, cur, thr))
    rate_b = f["slope"] / 100 * size if f else None
    if not f or conf == "faible" and not f["flat"]:
        detail = f"{_fb(free)} disponibles. Historique insuffisant ({len(pts)} points) pour une tendance fiable."
    elif f["flat"] or f["slope"] <= 0:
        detail = f"{_fb(free)} disponibles ; consommation stable sur {_fdur(f['span'])} : aucune saturation prévisible."
    else:
        detail = (f"{_fb(free)} disponibles ; consommation de {_fb(rate_b)}/jour sur {_fdur(f['span'])}"
                  + (f" (hors {jumps} nettoyage{'s' if jumps > 1 else ''} ponctuel{'s' if jumps > 1 else ''})" if jumps else "")
                  + (f" : seuil de {thr:.0f} % atteint dans {_fdur(eta)} au rythme actuel." if eta and eta <= 730
                     else " : saturation au-delà de 2 ans au rythme actuel."))
    return _item("homelab.rootfs", "Disque système du homelab (/)", "Espace utilisé (/)", cur, "%", "homelab",
                 trend=f["slope"] if f else None, eta_days=eta, confidence=conf,
                 severity=max(_sev_eta(eta), _sev_level(cur, 85, thr), key=lambda x: -SEV_ORDER[x]),
                 detail=detail, series=_series(pts), threshold=thr, fit_=f, trend_bytes_per_day=_r(rate_b),
                 source='node_filesystem_avail_bytes{mountpoint="/"}')


def fc_nas_array():
    """Array + cache additionnés : le mover déplace le cache vers l'array chaque nuit, la somme ne bouge pas avec lui."""
    disks = (STATE.get("slow", "nas") or {}).get("disks") or {}
    sizes, used, arr_used, arr_size = {}, {}, 0, 0
    for n, d in disks.items():
        if (re.fullmatch(r"disk\d+", n) or n == "cache") and d.get("fsSize") and d.get("fsFree"):
            try:
                sizes[n] = int(d["fsSize"]) * 1024
                used[n] = (int(d["fsSize"]) - int(d["fsFree"])) * 1024
            except ValueError:
                continue
            if n != "cache":
                arr_used += used[n]
                arr_size += sizes[n]
    if not arr_size:
        return None
    total = sum(sizes.values())
    cur = 100 * sum(used.values()) / total
    by_t = {}
    for lbl, pts in vm_range('infradash_disk_used_percent{host="nas",disk=~"disk[0-9]+|cache"}', 30 * DAY, 1800):
        if lbl.get("disk") in sizes:
            for t, v in pts:
                by_t.setdefault(t, {})[lbl["disk"]] = v
    vmpts = [(t, sum(row[d] / 100 * sizes[d] for d in sizes) / total * 100) for t, row in sorted(by_t.items()) if len(row) == len(sizes)]
    loc = []
    for p in _HIST["points"]:
        if p.get("array") and p.get("cache") and "cache" in sizes:
            loc.append((float(p["t"]), 100 * (p["array"][0] + p["cache"][0]) / (p["array"][1] + p["cache"][1])))
    pts = _merge(vmpts, loc, [(time.time(), cur)])
    adj, jumps = dejump(pts, min_abs=0.05)
    f = fit(adj)
    thr = 95.0
    eta, conf = _gate(f, _eta(f, cur, thr))
    if f and f["span"] < 1:
        eta, conf = None, "faible"
    rate_b = f["slope"] / 100 * total if f else None
    free = total - sum(used.values())
    full = sorted(((100 * used[n] / s, n) for n, s in sizes.items() if n != "cache"), reverse=True)
    head = (f"{_fb(free)} libres sur {_fb(total)} (array {_fr(100 * arr_used / arr_size, 0)} %"
            + (f", cache {_fr(100 * used['cache'] / sizes['cache'], 0)} %" if "cache" in sizes else "") + "). ")
    if not f or f["span"] < 1:
        detail = head + (f"Historique de {_fdur(f['span']) if f else '0 h'} seulement : tendance fiable après quelques jours de mesures. "
                         "Array et cache sont additionnés pour que les transferts du mover ne passent pas pour de la croissance.")
    elif f["flat"] or f["slope"] <= 0:
        detail = head + f"Volume stable sur {_fdur(f['span'])}."
    else:
        detail = head + (f"+{_fb(rate_b)}/jour sur {_fdur(f['span'])}"
                         + (f" : {thr:.0f} % atteints dans {_fdur(eta)}." if eta and eta <= 730 else
                            " : tendance encore incertaine." if conf == "faible" else " : pas de saturation avant 2 ans."))
    detail += f" Disque le plus plein : {full[0][1]} ({_fr(full[0][0], 0)} %)."
    items = [_item("nas.array", "Stockage du NAS (array + cache)", "Volume occupé (array + cache)", cur, "%", "nas",
                   trend=f["slope"] if f else None, eta_days=eta, confidence=conf,
                   severity=max(_sev_eta(eta, 14, 60), _sev_level(cur, 90, thr), key=lambda x: -SEV_ORDER[x]),
                   detail=detail, series=_series(pts), threshold=thr, fit_=f, trend_bytes_per_day=_r(rate_b),
                   source="infradash_disk_used_percent (disques + cache) + historique local")]
    for pct, n in full:
        if pct >= 90:
            items.append(_item(f"nas.{n}", f"{n} presque plein", "Remplissage du disque", pct, "%", "nas",
                               severity="crit" if pct >= 95 else "warn", horizon="7j", confidence="forte", threshold=95,
                               detail=f"{n} est à {_fr(pct, 0)} % : selon la méthode d'allocation du partage, Unraid peut continuer d'y écrire jusqu'à saturation."))
    return items


def _mover_times():
    crons = (STATE.get("slow", "nas_sched") or {}).get("crons") or []
    sch = next((c["schedule"] for c in crons if "mover start" in c.get("command", "")), None)
    if not sch:
        return None, None, None
    try:
        cr = Cron(sch)
        return cr.prev_run(), cr.next_run(), sch
    except ValueError:
        return None, None, sch


def fc_nas_cache():
    disks = (STATE.get("slow", "nas") or {}).get("disks") or {}
    c = disks.get("cache") or {}
    try:
        size = int(c["fsSize"]) * 1024
        cur = 100 * (1 - int(c["fsFree"]) / int(c["fsSize"]))
    except (KeyError, TypeError, ValueError, ZeroDivisionError):
        return None
    vmp = vm_range('infradash_disk_used_percent{host="nas",disk="cache"}', 7 * DAY, 600)
    pts = _merge(vmp[0][1] if vmp else [], _hist_series("cache"), [(time.time(), cur)])
    prev_mv, next_mv, sch = _mover_times()
    # Segment courant : depuis le point le plus bas atteint après le dernier passage du mover
    seg = pts
    if prev_mv:
        after = [p for p in pts if p[0] >= prev_mv.timestamp()]
        if after:
            i_min = min(range(len(after)), key=lambda i: after[i][1])
            seg = after[i_min:]
    f = fit(seg) if len(seg) >= 4 and seg[-1][0] - seg[0][0] >= 3600 else None
    hours = (next_mv.timestamp() - time.time()) / 3600 if next_mv else 24
    slope = f["slope"] if f and not f["flat"] else 0.0
    proj = cur + slope * hours / 24
    conf = "faible" if not f else ("moyenne" if f["n"] >= 6 and f["span"] >= 1 / 12 else "faible")
    eta = (100 - cur) / slope if slope > 0 and conf != "faible" else None
    eta = eta if eta is not None and eta * 24 <= hours else None  # saturation seulement si elle précède le mover
    days = {}
    for t, v in pts:
        k = datetime.fromtimestamp(t, TZ).strftime("%d/%m")
        days[k] = max(days.get(k, 0), v)
    peak_day, peak = max(days.items(), key=lambda kv: kv[1]) if days else (None, None)
    sev = _sev_level(cur, 85, 95)
    if conf != "faible":
        sev = max(sev, _sev_level(proj, 85, 95), key=lambda x: -SEV_ORDER[x])
    mv = f" ({_fd(next_mv.timestamp())})" if next_mv else ""
    detail = f"{_fr(cur, 0)} % utilisés ({_fb(size * (1 - cur / 100))} libres). "
    if not f:
        detail += "Pas encore assez de mesures depuis le dernier mover pour estimer le rythme d'écriture."
    elif slope == 0:
        detail += f"Stable depuis la dernière vidange : pas de risque avant le prochain mover{mv}."
    else:
        rate = f"{_fr(slope / 24, 1)} pt/h" if abs(slope / 24) >= 0.05 else f"{_fr(slope, 1)} pt/jour"
        detail += (f"Depuis la dernière vidange, {'+' if slope > 0 else ''}{rate} : ~{_fr(min(max(proj, 0), 100), 0)} % "
                   f"attendus avant le prochain mover{mv}" + (" (estimation à confirmer, peu de mesures)." if conf == "faible" else "."))
    if peak is not None:
        detail += f" Pic sur 7 j : {_fr(peak, 0)} % (le {peak_day})."
    return _item("nas.cache", "Cache NVMe du NAS avant le prochain mover", "Remplissage du cache (/mnt/cache)", cur, "%", "nas",
                 trend=slope if f else None, eta_days=eta, confidence=conf, severity=sev, horizon="24h", detail=detail,
                 series=_series(pts), threshold=100, fit_=f,
                 projection=[[int(time.time()), _r(cur)], [int(time.time() + hours * 3600), _r(min(max(proj, 0), 100))]] if f else None,
                 projected_at_mover=_r(min(max(proj, 0), 100)) if f else None, mover_next=next_mv.isoformat() if next_mv else None,
                 mover_schedule=sch, peak_7d=_r(peak))


def fc_nas_docker():
    sched = STATE.get("slow", "nas_sched") or {}
    d = next((x for x in sched.get("df") or [] if x.get("target") == "/var/lib/docker"), None)
    if not d or not d.get("size"):
        return None
    cur = 100 * d["used"] / d["size"]
    pts = _merge(_hist_series("docker"), [(float(sched.get("t") or time.time()), cur)])
    adj, jumps = dejump(pts, min_abs=0.5)
    f = fit(adj) if len(pts) >= 6 and pts[-1][0] - pts[0][0] >= 6 * 3600 else None
    thr = 90.0
    eta, conf = _gate(f, _eta(f, cur, thr))
    free = d["size"] - d["used"]
    if not f:
        span_h = (pts[-1][0] - pts[0][0]) / 3600 if len(pts) > 1 else 0
        detail = (f"{_fb(d['used'])} utilisés sur {_fb(d['size'])} ({_fb(free)} libres). Historique local en cours de constitution "
                  f"({len(pts)} mesure{'s' if len(pts) > 1 else ''} sur {_fr(span_h, 0)} h) : tendance disponible après 6 h de mesures.")
    elif f["flat"] or f["slope"] <= 0:
        detail = f"{_fb(d['used'])} sur {_fb(d['size'])} ; stable sur {_fdur(f['span'])}."
    else:
        detail = (f"{_fb(d['used'])} sur {_fb(d['size'])} ; +{_fb(f['slope'] / 100 * d['size'])}/jour (images, journaux, volumes)"
                  + (f" : {thr:.0f} % dans {_fdur(eta)}. Au-delà, les conteneurs plantent." if eta else " (tendance encore incertaine)."))
    return _item("nas.dockerimg", "Image Docker du NAS (docker.img)", "Remplissage de docker.img", cur, "%", "nas",
                 trend=f["slope"] if f else None, eta_days=eta, confidence=conf,
                 severity=max(_sev_eta(eta), _sev_level(cur, 80, thr), key=lambda x: -SEV_ORDER[x]),
                 detail=detail, series=_series(pts), threshold=thr, fit_=f, source="df /var/lib/docker (historique local)")


# --------------------------------------------------------------------------- sauvegardes
def fc_backups():
    chains = (STATE.get("derived", "backups") or {}).get("chains") or []
    disks = (STATE.get("slow", "nas") or {}).get("disks") or {}
    free = 0
    for n, d in disks.items():
        if re.fullmatch(r"disk\d+", n) and d.get("fsFree"):
            try:
                free += int(d["fsFree"]) * 1024
            except ValueError:
                pass
    items = []
    for c in chains:
        sizes = [(float(t), float(s)) for t, s in (c.get("sizes") or []) if s]
        if not sizes:
            continue
        cur = sizes[-1][1]
        # Palier : changement brutal de taille (nouveau contenu sauvegardé) ; la tendance se calcule après le dernier palier
        step = None
        for i in range(len(sizes) - 1, 0, -1):
            a, b = sizes[i - 1][1], sizes[i][1]
            if a and abs(b - a) / a > 0.3:
                step = (sizes[i][0], a, b)
                break
        seg = [p for p in sizes if not step or p[0] >= step[0]]
        f = fit(seg) if len(seg) >= 3 else None
        conf = _confidence(f) if f else "faible"
        slope = f["slope"] if f and not f["flat"] and conf != "faible" else 0.0
        gaps = [b[0] - a[0] for a, b in zip(sizes, sizes[1:]) if b[0] > a[0]]
        per_day = DAY / _median(gaps) if gaps else 1.0
        m = re.findall(r"\((\d+)\)", c.get("dest", ""))
        keep = int(m[-1]) if m else None
        total = c.get("total") or sum(s for _, s in sizes)
        truncated = c.get("id") == "clawhost" and c.get("count", 0) >= 40  # l'inventaire NAS ne liste que les 40 derniers dossiers

        def proj(days):
            size_then = max(0.0, cur + slope * days)
            if keep:  # rotation connue : N archives conservées au maximum
                return min(keep, c.get("count", 0) + per_day * days) * (cur + size_then) / 2 if c.get("count", 0) < keep else keep * size_then
            return total + per_day * days * (cur + size_then) / 2  # sans purge connue : tout s'accumule
        p30, p90 = proj(30), proj(90)
        growth_m = 100 * slope * 30 / cur if cur else 0
        added90 = max(0.0, p90 - total)
        share = 100 * added90 / free if free else None
        sev = "warn" if (share is not None and share > 5) or growth_m > 50 else "info"
        detail = f"Dernière : {_fb(cur)}"
        if step:
            detail += f" ; palier le {_fd(step[0], False)} ({_fb(step[1])} → {_fb(step[2])})"
        if f and conf != "faible":
            detail += (f" ; {'+' if slope >= 0 else ''}{_fb(slope * 30)} par mois et par sauvegarde depuis" if slope
                       else " ; taille stable depuis") + f" {_fdur(f['span'])}."
        else:
            detail += f" ; {len(seg)} sauvegarde(s) seulement{' depuis ce palier' if step else ''} : pas de tendance fiable."
        detail += (f" Occupation actuelle {_fb(total)}{' (40 derniers dossiers listés)' if truncated else ''} ; "
                   f"estimée à {_fb(p30)} dans 30 j et {_fb(p90)} dans 90 j "
                   + (f"(rotation de {keep} archives)." if keep else "(aucune purge constatée : tout s'accumule).")
                   + (f" Soit {_fr(share, 1)} % de l'espace libre de l'array en 90 j." if share is not None and not keep else ""))
        items.append(_item(f"backup.{c['id']}", f"Sauvegarde {c['label']} : volume", "Taille d'une sauvegarde", cur, "o",
                           c.get("from", "nas"), trend=slope if f else None, confidence=conf, severity=sev,
                           horizon="90j", detail=detail, series=_series(sizes, nd=0), fit_=f,
                           projection=[[int(time.time()), _r(cur)], [int(time.time() + 90 * DAY), _r(max(0.0, cur + slope * 90))]],
                           total_now=_r(total), total_30d=_r(p30), total_90d=_r(p90), retention=keep, per_day=_r(per_day, 2)))
    return items


# --------------------------------------------------------------------------- contrôle de parité
def fc_parity():
    arr = (STATE.get("live", "nas") or {}).get("array") or {}
    sched = STATE.get("slow", "nas_sched") or {}
    plog = [p for p in sched.get("parity_log") or [] if p.get("exit") == 0 and p.get("duration", 0) > 3600]
    typ = _median([p["duration"] for p in plog[-8:]]) if plog else None
    typ_speed = _median([p["speed"] for p in plog[-8:] if p.get("speed")]) if plog else None
    try:
        pos = int(arr.get("mdResyncPos") or 0)
        size = int(arr.get("mdResyncSize") or arr.get("mdResync") or 0)
        started = int(arr.get("sbSynced") or 0)
        errs = int(arr.get("sbSyncErrs") or 0)
        db, dt = int(arr.get("mdResyncDb") or 0), int(arr.get("mdResyncDt") or 0)
    except ValueError:
        pos = size = started = errs = db = dt = 0
    crons = sched.get("crons") or []
    sch = next((c["schedule"] for c in crons if "mdcmd check" in c.get("command", "")), None)
    nxt = None
    if sch:
        try:
            nxt = Cron(sch).next_run()
        except ValueError:
            nxt = None
    if not (pos and size):
        if not nxt:
            return None
        eta = (nxt.timestamp() - time.time()) / DAY
        return _item("nas.parity", "Prochain contrôle de parité", "Échéance du contrôle planifié", None, "", "nas",
                     eta_days=eta, confidence="forte", severity="info",
                     detail=f"Planifié le {_fd(nxt.timestamp())}" + (f" ; durée habituelle ~{_fdur(typ / DAY)} (médiane des derniers contrôles)"
                                                                     ", disques très sollicités pendant ce temps." if typ else "."))
    pct = 100 * pos / size
    now = time.time()
    elapsed = now - started if started else 0
    avg_speed = pos * 1024 / elapsed if elapsed > 1800 else None          # octets/s depuis le début
    inst_speed = db * 1024 / dt if db > 0 and dt > 0 else None              # octets/s instantané (Unraid)
    vmp = vm_range('infradash_parity_progress_percent{host="nas"}', 2 * DAY, 300)
    pts = _merge([(t, v) for t, v in (vmp[0][1] if vmp else []) if v > 0 and (not started or t >= started)], [(now, pct)])
    hour = [p for p in pts if p[0] >= now - 3600]
    f1 = fit(hour) if len(hour) >= 6 else None
    recent_speed = f1["slope"] / 100 * size * 1024 / DAY if f1 and f1["slope"] > 0 else inst_speed
    remaining = (size - pos) * 1024
    eta_avg = remaining / avg_speed / DAY if avg_speed else None
    eta_now = remaining / recent_speed / DAY if recent_speed else None
    eta = eta_avg if eta_avg is not None else eta_now  # le rythme moyen intègre les heures chargées (mover, sauvegardes)
    slow = avg_speed and typ_speed and avg_speed < 0.5 * typ_speed
    overlap = nxt and eta and now + eta * DAY > nxt.timestamp()
    sev = "warn" if slow or (eta and eta > 3) or overlap else "info"
    f = fit(pts) if len(pts) >= 6 else None
    conf = "moyenne" if avg_speed and elapsed > 6 * 3600 else "faible"
    if conf == "moyenne" and eta_now and eta_avg and 0.67 <= eta_now / eta_avg <= 1.5 and elapsed > 12 * 3600:
        conf = "forte"  # rythmes moyen et récent cohérents
    nas = STATE.get("live", "nas") or {}
    detail = (f"{_fr(pct, 1)} % vérifiés" + (f", démarré le {_fd(started)}" if started else "") + ". "
              + (f"Rythme moyen {_fr(avg_speed / 1e6, 1)} Mo/s" if avg_speed else "")
              + (f" (dernière heure : {_fr(recent_speed / 1e6, 1)} Mo/s)" if recent_speed and avg_speed else
                 f"Rythme récent {_fr(recent_speed / 1e6, 1)} Mo/s" if recent_speed else "")
              + (f" contre ~{_fr(typ_speed / 1e6, 0)} Mo/s d'habitude" if typ_speed else "")
              + (f" : fin estimée le {_fd(now + eta * DAY)} (dans {_fdur(eta)})" if eta else "")
              + (f", ou dans {_fdur(eta_now)} si le rythme de la dernière heure se maintient" if eta_now and eta and abs(eta_now - eta) / eta > 0.25 else "")
              + "."
              + (f" Pendant ce temps : iowait {_fr(nas.get('iowait', 0), 0)} %, charge {_fr((nas.get('load') or [0])[0], 1)} sur le NAS ;"
                 " Jellyfin, Immich, le mover et les sauvegardes nocturnes ralentissent le contrôle (et inversement)." if nas.get("iowait") is not None else "")
              + (f" {errs:,} erreurs de parité relevées.".replace(",", " ") if errs else "")
              + (f" Le contrôle mensuel planifié ({_fd(nxt.timestamp())}) tombera avant la fin." if overlap else ""))
    rate = 100 * avg_speed / (size * 1024) * DAY if avg_speed else (100 * recent_speed / (size * 1024) * DAY if recent_speed else None)
    return _item("nas.parity", "Fin du contrôle de parité en cours", "Progression du contrôle", pct, "%", "nas",
                 trend=rate, eta_days=eta, confidence=conf, severity=sev, detail=detail, series=_series(pts), threshold=100,
                 fit_=f, projection=[[int(now), _r(pct)], [int(now + eta * DAY), 100]] if eta else None,
                 speed_bps=_r(avg_speed), recent_speed_bps=_r(recent_speed), typical_speed_bps=_r(typ_speed), errors=errs,
                 eta_days_recent=_r(eta_now, 2), typical_duration_days=_r(typ / DAY if typ else None, 2))


# --------------------------------------------------------------------------- expirations
def _parse_date(s):
    if not s:
        return None
    if isinstance(s, (int, float)):
        return datetime.fromtimestamp(float(s), timezone.utc)
    s = str(s).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d", "%Y-%m"):
        try:
            d = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=TZ)
        except ValueError:
            continue
    return None


def fc_certs():
    eps = [e for e in (STATE.get("slow", "public") or {}).get("endpoints") or [] if isinstance(e.get("cert_days"), (int, float))]
    if not eps:
        return None
    eps.sort(key=lambda e: e["cert_days"])
    items = []
    for i, e in enumerate(eps):
        d = e["cert_days"]
        if i > 0 and d >= 21:
            break
        sev = "crit" if d <= 7 else "warn" if d <= 20 else "info"
        others = f" Les {len(eps) - 1} autres certificats expirent plus tard (≥ {eps[1]['cert_days']} j)." if i == 0 and len(eps) > 1 else ""
        items.append(_item(f"cert.{e['domain']}", f"Certificat TLS {e['domain']}", "Jours avant expiration", d, "j", "internet",
                           trend=-1, eta_days=float(d), confidence="forte", severity=sev,
                           detail=(f"Émis par {e.get('issuer') or '?'}, expire le {_fd(time.time() + d * DAY, False)}. "
                                   "Let's Encrypt (NPM) renouvelle à J-30 : sous 20 j, le renouvellement automatique a échoué." + others)))
    return items


def fc_tailscale():
    ts = STATE.get("live", "tailscale") or {}
    nodes = list(ts.get("peers") or [])
    if ts.get("self"):
        nodes.append({**ts["self"], "dns": ts["self"].get("host"), "self": True, "online": True})
    items = []
    now = datetime.now(timezone.utc)
    for p in nodes:
        dt = _parse_date(p.get("key_expiry"))
        if not dt:
            continue
        days = (dt - now).total_seconds() / DAY
        if days < 0 or days > 90:
            continue  # les clés déjà expirées relèvent des diagnostics, pas des prévisions
        name = p.get("dns") or p.get("host")
        items.append(_item(f"ts.{name}", f"Clé Tailscale de {name}", "Jours avant expiration de la clé", days, "j", "tailscale",
                           trend=-1, eta_days=days, confidence="forte", severity=_sev_eta(days, 7, 30),
                           detail=(f"Expire le {_fd(dt.timestamp())}{' (ce nœud)' if p.get('self') else ''} ; "
                                   f"{'en ligne' if p.get('online') else 'hors ligne'}. Sans ré-authentification, le nœud décroche du tailnet. "
                                   "Pour un serveur : console Tailscale → Machines → « Disable key expiry »."),
                           ))
    return items


def fc_eol():
    """Fins de support (slow.vulns.eol) : échéances à venir une par une, composants déjà hors support regroupés."""
    eol = (STATE.get("slow", "vulns") or {}).get("eol") or []
    now = datetime.now(timezone.utc)
    past, items = [], []
    for e in eol:
        dt = _parse_date(e.get("eol_date"))
        if not dt:
            continue  # « en retard » sur la dernière version sans date de fin : relève de la vue vulnérabilités
        days = (dt - now).total_seconds() / DAY
        label = f"{e.get('component') or e.get('product') or '?'} {e.get('cycle') or ''}".strip()
        where = e.get("container") or e.get("host") or "?"
        nxt = f" Branche maintenue conseillée : {e['next_cycle']}." if e.get("next_cycle") else ""
        if days < 0:
            past.append((days, label, where, e, nxt))
            continue
        if days > 180:
            continue
        items.append(_item(f"eol.{e.get('host', '')}.{e.get('component_id') or label}", f"Fin de support : {label}",
                           "Jours avant fin de support", days, "j", e.get("host") or "", trend=-1, eta_days=days, confidence="forte",
                           severity="warn" if days <= 30 or e.get("exposure") == "internet" else "info",
                           detail=f"{label} ({where}) ne recevra plus de correctifs de sécurité après le {_fd(dt.timestamp(), False)}." + nxt))
    if past:
        past.sort(key=lambda x: x[0])
        hosts = sorted({x[3].get("host") for x in past if x[3].get("host")})
        inet = [x for x in past if x[3].get("exposure") == "internet"]
        items.append(_item("eol.past", f"{len(past)} composant(s) déjà hors support", "Composants sans correctifs de sécurité",
                           len(past), "", hosts[0] if len(hosts) == 1 else "", horizon="24h", confidence="forte", severity="warn",
                           detail="; ".join(f"{lbl} ({w}) depuis le {_fd(_parse_date(e['eol_date']).timestamp(), False)}" for _, lbl, w, e, _n in past[:6])
                           + (f" ; et {len(past) - 6} autre(s)" if len(past) > 6 else "") + "."
                           + (f" Dont {len(inet)} exposé(s) sur Internet." if inet else "") + " Détail et chemin de migration dans la vue Vulnérabilités."))
    return items

# --------------------------------------------------------------------------- tendances
def fc_disk_temps():
    res = vm_range('max_over_time(infradash_disk_temp_celsius{host="nas"}[1h])', 14 * DAY, 3600)
    if not res:
        return None
    nas_disks = (STATE.get("slow", "nas") or {}).get("disks") or {}
    best = None
    for lbl, pts in res:
        disk = lbl.get("disk", "?")
        if not pts:
            continue
        thr = 70.0 if disk.startswith("cache") else 45.0
        cur = pts[-1][1]
        try:
            cur = float(nas_disks.get(disk, {}).get("temp")) if str(nas_disks.get(disk, {}).get("temp", "")).isdigit() else cur
        except ValueError:
            pass
        f = fit(pts)
        eta = _gate(f, _eta(f, cur, thr), max_extrap=5)[0] if f and f["span"] >= 2 else None
        score = (eta if eta is not None else 1e9, -(cur / thr))
        if best is None or score < best[0]:
            best = (score, disk, cur, thr, f, eta, pts)
    if not best:
        return None
    _, disk, cur, thr, f, eta, pts = best
    tops = sorted(((float(d["temp"]), n) for n, d in nas_disks.items() if str(d.get("temp", "")).isdigit()), reverse=True)[:3]
    par = int((STATE.get("live", "nas") or {}).get("array", {}).get("mdResyncPos") or 0) > 0
    span = f["span"] if f else 0
    detail = ("Plus chauds : " + ", ".join(f"{n} {t:.0f} °C" for t, n in tops) + ". " if tops else "")
    if f and span >= 2 and not f["flat"]:
        detail += f"{disk} : {'+' if f['slope'] >= 0 else ''}{_fr(f['slope'], 2)} °C/jour (max horaire sur {_fdur(span)})"
        detail += f", {thr:.0f} °C atteints dans {_fdur(eta)}." if eta else "."
    else:
        detail += f"Pas de dérive mesurable sur {_fdur(span)} d'historique" + (" (tendance fiable après 2 j)." if span < 2 else ".")
    if par:
        detail += " Le contrôle de parité en cours fait tourner tous les disques à plein régime (températures plus hautes qu'à l'ordinaire)."
    sev = "warn" if cur >= thr or (eta is not None and eta <= 7) else "info"
    return _item("nas.disktemp", f"Températures des disques (plus exposé : {disk})", f"Température max horaire de {disk}", cur, "°C", "nas",
                 trend=f["slope"] if f and span >= 2 else None, eta_days=eta, confidence=_confidence(f, eta) if span >= 2 else "faible",
                 severity=sev, detail=detail, series=_series(pts, nd=1), threshold=thr, fit_=f)


def _fc_mem(host, query, label, live_key):
    res = vm_range(query, 14 * DAY, 3600)
    pts = res[0][1] if res and res[0][1] else []
    live = STATE.get("live", live_key) or {}
    if isinstance(live.get("mem"), (int, float)):
        pts = _merge(pts, [(time.time(), float(live["mem"]))])
    if not pts:
        return None
    cur = pts[-1][1]
    f = fit(pts)
    thr = 90.0
    eta, conf = _gate(f, _eta(f, cur, thr), max_extrap=5)
    span = f["span"] if f else 0
    if span < 1:
        eta, conf = None, "faible"
    if not f or span < 1:
        detail = f"{_fr(cur, 0)} % utilisés. Historique de {_fdur(span)} seulement : tendance non fiable avant quelques jours."
    elif f["flat"]:
        detail = f"{_fr(cur, 0)} % utilisés ; stable sur {_fdur(span)} (moyennes horaires)."
    else:
        detail = (f"{_fr(cur, 0)} % utilisés ; {'+' if f['slope'] >= 0 else ''}{_fr(f['slope'], 2)} pt/jour sur {_fdur(span)}"
                  + (f" : {thr:.0f} % dans {_fdur(eta)} (fuite mémoire ou nouveau service ?)." if eta else
                     " (tendance encore incertaine)." if conf == "faible" else " : aucun seuil atteint dans un horizon crédible."))
    return _item(f"{host}.mem", f"Mémoire du {label}", "Mémoire utilisée", cur, "%", host,
                 trend=f["slope"] if f and span >= 1 else None, eta_days=eta, confidence=conf,
                 severity=max(_sev_eta(eta, 7, 30), _sev_level(cur, 85, thr), key=lambda x: -SEV_ORDER[x]),
                 detail=detail, series=_series(pts, nd=1), threshold=thr, fit_=f)


def fc_mem():
    return [x for x in (
        _fc_mem("nas", 'avg_over_time(infradash_mem_percent{host="nas"}[1h])', "NAS", "nas"),
        _fc_mem("homelab", '100*(1 - avg_over_time(node_memory_MemAvailable_bytes{job="node-exporter"}[1h])'
                           '/avg_over_time(node_memory_MemTotal_bytes{job="node-exporter"}[1h]))', "homelab", "homelab"),
    ) if x]


def fc_speedtest():
    res = vm_range("max_over_time(speedtest_download_bits_per_second[3h])/1e6", 30 * DAY, 3 * 3600)
    pts = res[0][1] if res and res[0][1] else []
    if len(pts) < 4:
        return None
    f = fit(pts)
    now = time.time()
    last7 = [v for t, v in pts if t >= now - 7 * DAY]
    before = [v for t, v in pts if t < now - 7 * DAY]
    m7, mb = _median(last7), _median(before)
    drop = 100 * (mb - m7) / mb if m7 is not None and mb else None
    cur = pts[-1][1]
    sev = "warn" if drop is not None and drop > 20 else "info"
    detail = f"Dernier test {_fr(cur, 0)} Mbit/s"
    if m7 is not None and mb:
        detail += f" ; médiane 7 j {_fr(m7, 0)} Mbit/s contre {_fr(mb, 0)} Mbit/s les 3 semaines précédentes ({'-' if drop > 0 else '+'}{_fr(abs(drop), 1)} %)."
    else:
        detail += "."
    if f and not f["flat"]:
        detail += f" Tendance {'+' if f['slope'] >= 0 else ''}{_fr(f['slope'], 1)} Mbit/s par jour."
    elif f:
        detail += " Débit stable."
    return _item("net.speedtest", "Débit Internet (speedtest)", "Débit descendant", cur, "Mbit/s", "internet",
                 trend=f["slope"] if f else None, confidence=_confidence(f), severity=sev, horizon="30j", detail=detail,
                 series=_series(pts, nd=0), fit_=f, drop_pct=_r(drop, 1))


def fc_dns():
    res = vm_range('quantile_over_time(0.5, infradash_dns_ms{host="homelab"}[1h])', 14 * DAY, 3600)
    pts = res[0][1] if res and res[0][1] else []
    dh = [(float(t), float(v)) for t, v in (STATE.get("live", "dns_hist") or []) if v is not None]
    if dh:
        pts = _merge(pts, [(dh[-1][0], _median([v for _, v in dh[-20:]]))])
    if len(pts) < 3:
        return None
    f = fit(pts)
    cur = pts[-1][1]
    thr = 100.0
    eta, conf = _gate(f, _eta(f, cur, thr), max_extrap=5) if f and f["span"] >= 1 else (None, "faible")
    fails = sum(1 for _, v in (STATE.get("live", "dns_hist") or []) if v is None)
    span = f["span"] if f else 0
    detail = f"Médiane horaire {_fr(cur, 0)} ms (AdGuard → Unbound, requête debian.org)."
    if f and span >= 1 and not f["flat"]:
        detail += f" {'+' if f['slope'] >= 0 else ''}{_fr(f['slope'], 2)} ms/jour sur {_fdur(span)}" + (f" : {thr:.0f} ms dans {_fdur(eta)}." if eta else ".")
    else:
        detail += f" Stable sur {_fdur(span)}." if span >= 1 else f" Historique de {_fdur(span)} seulement."
    if fails:
        detail += f" {fails} échec(s) de résolution sur les 2 dernières heures."
    sev = "warn" if cur >= thr or fails >= 3 or (eta is not None and eta <= 7) else "info"
    return _item("net.dns", "Latence DNS du réseau (AdGuard)", "Temps de résolution", cur, "ms", "homelab",
                 trend=f["slope"] if f and span >= 1 else None, eta_days=eta, confidence=conf, severity=sev,
                 detail=detail, series=_series(pts, nd=0), threshold=thr, fit_=f)


_RESTART_RX = re.compile(r"(→ (exited|dead|restarting)|a redémarré|recréé|Conteneur arrêté)")


def _ev_name(title):
    """Nom du conteneur dans un titre d'événement (« x : running → exited », « x a redémarré », « Conteneur recréé : x »)."""
    m = re.match(r"^Conteneur (?:recréé|arrêté|supprimé) : (.+)$", title)
    return m.group(1).strip() if m else re.split(r" : | a redémarré", title)[0].strip()


def _container_events():
    seen, evs = set(), []
    lines = []
    try:  # le journal disque couvre plus loin que les 400 événements gardés en mémoire
        with open(EVENTS_FILE) as f:
            lines = f.readlines()[-3000:]
    except OSError:
        pass
    for e in [json.loads(x) for x in lines if x.strip().startswith("{")] + STATE.recent_events(400):
        k = (round(e.get("t", 0), 1), e.get("title"))
        if k in seen:
            continue
        seen.add(k)
        if e.get("kind") == "container" and _RESTART_RX.search(e.get("title", "")):
            evs.append(e)
    return evs


def _mass_cause(t):
    """Cause probable d'un arrêt collectif : mise à jour automatique planifiée (CA Auto Update) ou reboot/relance de Docker."""
    for c in (STATE.get("slow", "nas_sched") or {}).get("crons") or []:
        if "updateDocker.php" in c.get("command", ""):
            try:
                prev = Cron(c["schedule"]).prev_run(datetime.fromtimestamp(t + 60, TZ))
            except ValueError:
                continue
            if prev and 0 <= t - prev.timestamp() <= 1800:
                return f"coïncide avec la mise à jour automatique des conteneurs de {prev.strftime('%H:%M')}"
    up = (STATE.get("slow", "nas_sched") or {}).get("uptime") or 0
    if up and abs((time.time() - up) - t) < 900:
        return "redémarrage du NAS"
    return "reboot du NAS ou relance de Docker"


def fc_restarts():
    now = time.time()
    evs = sorted((e for e in _container_events() if e["t"] >= now - 14 * DAY), key=lambda e: e["t"])
    # Regroupement : ≥ 5 conteneurs touchés à moins de 5 min d'écart = épisode collectif (reboot, relance de Docker), compté une fois
    groups, cur = [], []
    for e in evs:
        if cur and e["t"] - cur[-1]["t"] > 300:
            groups.append(cur)
            cur = []
        cur.append(e)
    if cur:
        groups.append(cur)
    mass = [g for g in groups if len({_ev_name(x["title"]) for x in g}) >= 5]
    single = [x for g in groups if len({_ev_name(y["title"]) for y in g}) < 5 for x in g]
    per_day = {}
    for t in [x["t"] for x in single] + [g[0]["t"] for g in mass]:
        k = int((now - t) // DAY)
        per_day[k] = per_day.get(k, 0) + 1
    span_days = min(14, max(1, int((now - evs[0]["t"]) // DAY) + 1)) if evs else 1
    pts = [(now - (k + 0.5) * DAY, float(per_day.get(k, 0))) for k in range(span_days - 1, -1, -1)]
    f = fit(pts) if len(pts) >= 4 else None
    last7 = [x for x in single if x["t"] >= now - 7 * DAY]
    names, names24 = {}, {}
    for x in last7:
        nm = _ev_name(x["title"])
        names[nm] = names.get(nm, 0) + 1
        if x["t"] >= now - DAY:
            names24[nm] = names24.get(nm, 0) + 1
    unstable = sorted(((v, k) for k, v in names.items() if v >= 2), reverse=True)
    loop24 = sorted(k for k, v in names24.items() if v >= 3)
    mass7 = [g for g in mass if g[0]["t"] >= now - 7 * DAY]
    cur_rate = (len(last7) + len(mass7)) / 7
    sev = "warn" if loop24 or len(mass7) >= 2 else "info"
    detail = (f"Sur 7 j : {len(last7)} arrêt(s)/redémarrage(s) isolé(s) et {len(mass7)} épisode(s) collectif(s)"
              + (f" (dernier le {_fd(mass7[-1][0]['t'])}, {len({_ev_name(x['title']) for x in mass7[-1]})} conteneurs : "
                 + _mass_cause(mass7[-1][0]["t"]) + ")" if mass7 else "") + ".")
    if unstable:
        detail += " Les plus instables : " + ", ".join(f"{k} ({v}×)" for v, k in unstable[:4]) + "."
    if loop24:
        detail += " Boucle de redémarrage probable sur 24 h : " + ", ".join(loop24) + "."
    restarts = sorted(((c.get("restarts") or 0, c["name"]) for c in STATE.get("live", "nas_containers") or []
                       if (c.get("restarts") or 0) > 0), reverse=True)
    if restarts:
        detail += " Compteurs Docker de redémarrage automatique : " + ", ".join(f"{n} ({r})" for r, n in restarts[:4]) + "."
    if not evs:
        detail = "Aucun arrêt ni redémarrage de conteneur journalisé sur 14 j."
    return _item("docker.restarts", "Stabilité des conteneurs", "Arrêts/redémarrages par jour", cur_rate, "/j", "nas",
                 trend=(f["slope"] if not f["flat"] else 0.0) if f else None, confidence=_confidence(f) if f else "faible",
                 severity=sev, horizon="7j", detail=detail, series=[[int(t), v] for t, v in pts], fit_=f,
                 unstable=[{"name": k, "count": v} for v, k in unstable[:6]], mass_episodes_7d=len(mass7))


# --------------------------------------------------------------------------- orchestration
BUILDERS = [fc_parity, fc_nas_cache, fc_nas_array, fc_nas_docker, fc_homelab_root, fc_backups, fc_certs, fc_tailscale,
            fc_eol, fc_disk_temps, fc_mem, fc_speedtest, fc_dns, fc_restarts]


def run():
    """Calcule toutes les prévisions (appelé par le runner toutes les 10 min)."""
    t0 = time.time()
    try:
        _sample_history()
    except Exception as e:  # l'historique local ne doit pas bloquer les prévisions
        hist_err = f"historique : {type(e).__name__}: {e}"
    else:
        hist_err = None
    items, errors = [], [hist_err] if hist_err else []
    for fn in BUILDERS:
        try:
            r = fn()
        except Exception as e:  # une source en panne (VictoriaMetrics, état incomplet) n'empêche pas les autres
            errors.append(f"{fn.__name__} : {type(e).__name__}: {e}")
            continue
        if r:
            items.extend(r if isinstance(r, list) else [r])
    items.sort(key=lambda i: (SEV_ORDER.get(i["severity"], 3), i["eta_days"] if i["eta_days"] is not None else 1e9))
    out = {"items": items, "t": time.time(), "duration_ms": round((time.time() - t0) * 1000), "errors": errors,
           "history_points": len(_HIST["points"])}
    STATE.set("derived", "forecasts", out)
    return out
