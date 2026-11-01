#!/usr/bin/env python3
"""Active (ou désactive) l'exécution des commandes de correction depuis InfraDash.

Crée ~/.config/infradash/exec.json (mode 600) avec le HACHAGE scrypt d'une phrase secrète : la phrase elle-même n'est jamais stockée.
Sans ce fichier, les boutons « Exécuter » restent grisés et seule la copie des commandes est possible.

  python3 tools/exec-setup.py            # définir / changer la phrase secrète
  python3 tools/exec-setup.py --disable  # désactiver l'exécution
"""
import getpass
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from infradash import remedy  # noqa: E402

path = remedy.CFG_FILE
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
if "--disable" in sys.argv:
    try:
        os.remove(path)
        print("Exécution désactivée (fichier supprimé).")
    except FileNotFoundError:
        print("Déjà désactivée.")
    sys.exit(0)
a = getpass.getpass("Nouvelle phrase secrète (12 caractères minimum) : ")
if len(a) < 12:
    sys.exit("Trop courte : 12 caractères minimum.")
if a != getpass.getpass("Confirmez : "):
    sys.exit("Les deux saisies diffèrent.")
salt = secrets.token_bytes(16)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump({"enabled": True, "salt": salt.hex(), "hash": remedy.hash_pin(a, salt)}, f)
os.chmod(path, 0o600)
print(f"OK : {path} (mode 600). L'exécution est active ; redémarrage du dashboard inutile.")
