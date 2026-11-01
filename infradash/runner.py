"""Boucles de collecte en tâche de fond."""
import threading
import time
import traceback

from .state import STATE


_WAKE = {}   # nom de boucle -> Event : kick() la relance sans attendre la fin de son intervalle


def loop(name, interval, fn, initial_delay=0.0):
    wake = _WAKE.setdefault(name, threading.Event())

    def _run():
        time.sleep(initial_delay)
        while True:
            wake.clear()
            t0 = time.time()
            try:
                fn()
                STATE.mark(name, True, dur=time.time() - t0)
            except Exception as e:  # un collecteur en échec ne doit jamais arrêter les autres
                STATE.mark(name, False, f"{type(e).__name__}: {e}", dur=time.time() - t0)
                traceback.print_exc()
            wake.wait(max(0.2, interval - (time.time() - t0)))

    th = threading.Thread(target=_run, name=name, daemon=True)
    th.start()
    return th


def kick(*names):
    """Relance aussitôt des boucles déjà démarrées (ex. prévisions et notes après une revérification manuelle)."""
    for n in names:
        ev = _WAKE.get(n)
        if ev:
            ev.set()
