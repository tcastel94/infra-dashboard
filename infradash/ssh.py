"""Exécution SSH en lecture seule avec connexion persistante (ControlMaster) pour limiter la charge."""
import os
import subprocess
import threading
import time

from .config import DATA_DIR, SSH_KEY


class SSH:
    def __init__(self, user, host, port=22, key=None):
        self.user, self.host, self.port = user, host, port
        self.key = key or SSH_KEY   # clé dédiée (restreinte côté serveur) ou clé par défaut du homelab
        self.ok = None          # None = jamais tenté
        self.last_error = ""
        self.last_ok = 0
        self.lock = threading.Lock()
        self.cpath = os.path.join(DATA_DIR, f"ssh-{user}-{host}-{port}")

    def _base(self, timeout):
        return ["ssh", "-T", "-i", self.key, "-p", str(self.port), "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(timeout, 6)}",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "ControlMaster=auto", "-o", f"ControlPath={self.cpath}", "-o", "ControlPersist=300",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
                f"{self.user}@{self.host}"]

    def run(self, command, timeout=15):
        """Lance `command` (chaîne fixe définie dans le code) et renvoie stdout, ou None si échec."""
        try:
            p = subprocess.run(self._base(timeout) + [command], capture_output=True, text=True,
                               timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            self.last_error = "timeout"
            self.ok = False
            return None
        except Exception as e:  # noqa
            self.last_error = str(e)
            self.ok = False
            return None
        if p.returncode == 255:
            self.ok = False
            self.last_error = (p.stderr or "").strip()[-200:]
            return None
        self.ok = True
        self.last_ok = time.time()
        return p.stdout
