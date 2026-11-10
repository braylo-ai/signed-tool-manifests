"""Tool registry with versioned publication, compatibility gates and deferred loading."""

from __future__ import annotations

import copy
import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import evolution
from .manifest import build_manifest, sign


class PublishError(Exception):
    pass


class Registry:
    """Publisher side: keeps every version of every tool and signs a manifest per release.

    Clients see a cheap catalog (stubs) and fetch full definitions only on demand."""

    def __init__(self, publisher: str, key: Ed25519PrivateKey, clock=time.time):
        self.publisher = publisher
        self.key = key
        self.clock = clock
        self.versions: dict[str, dict[str, dict]] = {}  # name -> version -> definition
        self.current: dict[str, str] = {}  # name -> current version
        self.sequence = 0
        self.manifests: list[dict] = (
            []
        )  # every signed manifest ever issued (for replay tests)
        self.fetch_log: list[str] = []

    def publish(self, tool: dict) -> None:
        name, ver = tool["name"], tool["version"]
        if name in self.current:
            prev = self.versions[name][self.current[name]]
            change = evolution.classify(prev["inputSchema"], tool["inputSchema"])
            err = evolution.required_bump(
                prev["version"],
                ver,
                change,
                description_changed=prev["description"] != tool["description"],
            )
            if err:
                raise PublishError(f"{name}: {err}")
        self.versions.setdefault(name, {})[ver] = copy.deepcopy(tool)
        self.current[name] = ver

    def release(self, ttl: int = 86400) -> dict:
        self.sequence += 1
        tools = [self.versions[n][v] for n, v in self.current.items()]
        signed = sign(
            build_manifest(
                self.publisher, tools, self.sequence, int(self.clock()), ttl
            ),
            self.key,
        )
        self.manifests.append(signed)
        return copy.deepcopy(signed)

    # --- what a client fetches -----------------------------------------
    def fetch_definition(self, name: str, version: str) -> dict:
        self.fetch_log.append(f"{name}@{version}")
        return copy.deepcopy(self.versions[name][version])

    def full_catalog_bytes(self) -> int:
        return len(json.dumps([self.versions[n][v] for n, v in self.current.items()]))
