"""Calcul des scores de base CVSS (v3.0/v3.1 exact, v2 exact, v4 approché via les métriques v3) en stdlib."""
import math

# --- CVSS v3.x -----------------------------------------------------------------
_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x):
    """Arrondi supérieur à une décimale tel que défini par la spécification 3.1 (évite les erreurs flottantes)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse(vector):
    """'CVSS:3.1/AV:N/AC:L/...' -> ('3.1', {'AV': 'N', ...})."""
    if not vector:
        return None, {}
    parts = vector.strip().split("/")
    ver = "2.0"
    if parts and parts[0].upper().startswith("CVSS:"):
        ver = parts[0].split(":", 1)[1]
        parts = parts[1:]
    m = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            m[k.strip().upper()] = v.strip().upper()
    return ver, m


def score_v3(m):
    try:
        changed = m["S"] == "C"
        pr = (_PR_C if changed else _PR_U)[m["PR"]]
        iss = 1 - (1 - _V3["C"][m["C"]]) * (1 - _V3["I"][m["I"]]) * (1 - _V3["A"][m["A"]])
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _V3["AV"][m["AV"]] * _V3["AC"][m["AC"]] * pr * _V3["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if changed:
        return _roundup(min(1.08 * (impact + expl), 10))
    return _roundup(min(impact + expl, 10))


# --- CVSS v2 -------------------------------------------------------------------
_V2 = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "AU": {"M": 0.45, "S": 0.56, "N": 0.704},
    "C": {"N": 0.0, "P": 0.275, "C": 0.660},
    "I": {"N": 0.0, "P": 0.275, "C": 0.660},
    "A": {"N": 0.0, "P": 0.275, "C": 0.660},
}


def score_v2(m):
    try:
        impact = 10.41 * (1 - (1 - _V2["C"][m["C"]]) * (1 - _V2["I"][m["I"]]) * (1 - _V2["A"][m["A"]]))
        expl = 20 * _V2["AV"][m["AV"]] * _V2["AC"][m["AC"]] * _V2["AU"][m["AU"]]
    except KeyError:
        return None
    f = 0 if impact == 0 else 1.176
    return round(((0.6 * impact) + (0.4 * expl) - 1.5) * f, 1)


# --- CVSS v4 (approximation) -----------------------------------------------------
def v4_to_v3(m):
    """Projette un vecteur v4 sur les métriques v3 (approximation : AT:P -> AC:H, impact aval -> portée modifiée)."""
    try:
        sub = any(m.get(k, "N") in ("H", "L") for k in ("SC", "SI", "SA"))
        return {
            "AV": m["AV"], "AC": "H" if (m["AC"] == "H" or m.get("AT") == "P") else "L",
            "PR": m["PR"], "UI": "N" if m["UI"] == "N" else "R", "S": "C" if sub else "U",
            "C": m["VC"] if not sub else max(m["VC"], m.get("SC", "N"), key="NLH".index),
            "I": m["VI"] if not sub else max(m["VI"], m.get("SI", "N"), key="NLH".index),
            "A": m["VA"] if not sub else max(m["VA"], m.get("SA", "N"), key="NLH".index),
        }
    except KeyError:
        return None


def base_score(vector):
    """Renvoie (score, version, approx) ou (None, version, False) si vecteur illisible."""
    ver, m = parse(vector)
    if not m:
        return None, ver, False
    if ver and ver.startswith("3"):
        return score_v3(m), ver, False
    if ver and ver.startswith("4"):
        m3 = v4_to_v3(m)
        return (score_v3(m3) if m3 else None), ver, True
    if "AU" in m:
        return score_v2(m), "2.0", False
    return None, ver, False


def attack_vector(vector):
    """'N' (réseau), 'A' (adjacent), 'L' (local), 'P' (physique) ou None."""
    _, m = parse(vector)
    av = m.get("AV")
    return av if av in ("N", "A", "L", "P") else None


def label(score):
    """Libellé français de sévérité à partir d'un score de base."""
    if score is None:
        return "inconnue"
    if score >= 9.0:
        return "critique"
    if score >= 7.0:
        return "haute"
    if score >= 4.0:
        return "moyenne"
    if score > 0:
        return "basse"
    return "aucune"


# Libellés textuels (GitHub, OSV database_specific, Debian/Ubuntu) -> score indicatif
LABEL_SCORE = {"critical": 9.5, "high": 8.0, "important": 8.0, "moderate": 5.5, "medium": 5.5, "low": 3.0,
               "negligible": 1.0, "unimportant": 1.0}


def score_from_label(text):
    return LABEL_SCORE.get((text or "").strip().lower())
