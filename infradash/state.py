"""État partagé entre collecteurs et serveur web, journal d'événements."""
import json
import os
import threading
import time
from collections import deque

from .config import DATA_DIR

EVENTS_FILE = os.path.join(DATA_DIR, "events.jsonl")


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"hosts": {}, "live": {}, "slow": {}}
        self.version = 0
        self.events = deque(maxlen=400)
        self.collector_status = {}
        self._load_events()

    def _load_events(self):
        try:
            with open(EVENTS_FILE) as f:
                for line in f.readlines()[-400:]:
                    self.events.append(json.loads(line))
        except (OSError, ValueError):
            pass

    def set(self, section, key, value):
        with self.lock:
            self.data.setdefault(section, {})[key] = value
            self.version += 1

    def get(self, section, key, default=None):
        with self.lock:
            return self.data.get(section, {}).get(key, default)

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.data, default=str))

    def event(self, level, host, title, detail="", kind="info"):
        ev = {"t": time.time(), "level": level, "host": host, "title": title, "detail": detail, "kind": kind}
        with self.lock:
            self.events.append(ev)
        try:
            with open(EVENTS_FILE, "a") as f:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            if os.path.getsize(EVENTS_FILE) > 2_000_000:   # rotation simple
                with open(EVENTS_FILE) as f:
                    keep = f.readlines()[-1000:]
                with open(EVENTS_FILE, "w") as f:
                    f.writelines(keep)
        except OSError:
            pass

    def recent_events(self, n=150):
        with self.lock:
            return list(self.events)[-n:]

    def mark(self, name, ok, err="", dur=None):
        with self.lock:
            st = self.collector_status.setdefault(name, {"runs": 0, "errors": 0})
            st["runs"] += 1
            st["last"] = time.time()
            st["ok"] = ok
            if dur is not None:
                st["dur_ms"] = round(dur * 1000)
            if not ok:
                st["errors"] += 1
                st["last_error"] = str(err)[:300]


STATE = State()
