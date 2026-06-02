"""Per-node local object store.

Replaces the original ``scp`` / ``os.system`` file transfer (which only worked
on SCU's ECC cluster with pre-shared SSH) with a self-contained store that
keeps object bytes on local disk and lets the server stream them in-band.  This
makes the whole system runnable and testable on a single machine.

Each node owns a directory tree::

    <root>/<node-id>/objects/     # primary copies this node is responsible for
    <root>/<node-id>/backups/     # replicas held on behalf of other nodes
    <root>/<node-id>/manifest.json
"""
from __future__ import annotations

import json
import os
import threading
from typing import Optional

from .logutil import get_logger

log = get_logger("storage")


class Storage:
    def __init__(self, node_id: int, root: str):
        self.node_id = node_id
        self.base = os.path.join(root, str(node_id))
        self.obj_dir = os.path.join(self.base, "objects")
        self.bak_dir = os.path.join(self.base, "backups")
        self.manifest_path = os.path.join(self.base, "manifest.json")
        os.makedirs(self.obj_dir, exist_ok=True)
        os.makedirs(self.bak_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._manifest = self._load_manifest()

    # -- manifest ---------------------------------------------------------- #
    def _load_manifest(self) -> dict:
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path) as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                log.warning("manifest unreadable, starting fresh")
        return {"objects": [], "backups": []}

    def _save_manifest(self) -> None:
        with open(self.manifest_path, "w") as fh:
            json.dump(self._manifest, fh, indent=2)

    # -- primary objects --------------------------------------------------- #
    def put_object(self, name: str, data: bytes) -> None:
        with self._lock:
            with open(os.path.join(self.obj_dir, name), "wb") as fh:
                fh.write(data)
            if name not in self._manifest["objects"]:
                self._manifest["objects"].append(name)
                self._save_manifest()

    def get_object(self, name: str) -> Optional[bytes]:
        for directory in (self.obj_dir, self.bak_dir):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    return fh.read()
        return None

    def has_object(self, name: str) -> bool:
        return (os.path.isfile(os.path.join(self.obj_dir, name))
                or os.path.isfile(os.path.join(self.bak_dir, name)))

    # -- backups (replicas) ------------------------------------------------ #
    def put_backup(self, name: str, data: bytes) -> None:
        with self._lock:
            with open(os.path.join(self.bak_dir, name), "wb") as fh:
                fh.write(data)
            if name not in self._manifest["backups"]:
                self._manifest["backups"].append(name)
                self._save_manifest()

    def promote_backup(self, name: str) -> bool:
        """Move a backup into the primary set (used during recovery)."""
        with self._lock:
            src = os.path.join(self.bak_dir, name)
            if not os.path.isfile(src):
                return False
            os.replace(src, os.path.join(self.obj_dir, name))
            if name in self._manifest["backups"]:
                self._manifest["backups"].remove(name)
            if name not in self._manifest["objects"]:
                self._manifest["objects"].append(name)
            self._save_manifest()
            return True

    # -- listings ---------------------------------------------------------- #
    def list_objects(self) -> list[str]:
        with self._lock:
            return list(self._manifest["objects"])

    def list_backups(self) -> list[str]:
        with self._lock:
            return list(self._manifest["backups"])
