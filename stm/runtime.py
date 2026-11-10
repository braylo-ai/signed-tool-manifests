"""Agent runtime that only runs tools from verified, signed manifests."""

from __future__ import annotations

import json
import time
from typing import Callable

import jsonschema

from .manifest import ManifestError, TrustStore, fingerprint, verify
from .evolution import parse_semver


class ToolRefused(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code


class AgentRuntime:
    def __init__(
        self,
        trust: TrustStore,
        fetch: Callable[[str, str], dict],
        handlers: dict[str, Callable[[dict], object]],
        clock=time.time,
    ):
        self.trust = trust
        self.fetch = (
            fetch  # (name, version) -> full definition, e.g. Registry.fetch_definition
        )
        self.handlers = handlers
        self.clock = clock
        self.high_water: dict[str, int] = (
            {}
        )  # publisher -> highest manifest sequence accepted
        self.pinned: dict[str, str] = (
            {}
        )  # tool -> lowest version we will accept from now on
        self.stubs: dict[str, dict] = {}  # tool name -> manifest entry
        self.loaded: dict[str, dict] = {}  # tool name -> verified full definition
        self.audit: list[dict] = []

    def _refuse(self, code: str, detail: str):
        self.audit.append({"refused": code, "detail": detail})
        raise ToolRefused(code, detail)

    def install(self, signed_manifest: dict) -> list[str]:
        try:
            body = verify(signed_manifest, self.trust, int(self.clock()))
        except ManifestError as e:
            self._refuse(e.code, str(e))
        pub = body["publisher"]
        if body["sequence"] <= self.high_water.get(pub, 0):
            self._refuse(
                "rollback",
                f"manifest sequence {body['sequence']} <= seen {self.high_water[pub]}",
            )
        for entry in body["tools"]:
            pin = self.pinned.get(entry["name"])
            if pin and parse_semver(entry["version"]) < parse_semver(pin):
                self._refuse(
                    "downgrade", f"{entry['name']} {entry['version']} < pinned {pin}"
                )
        self.high_water[pub] = body["sequence"]
        for entry in body["tools"]:
            self.pinned[entry["name"]] = entry["version"]
            if (
                self.stubs.get(entry["name"], {}).get("fingerprint")
                != entry["fingerprint"]
            ):
                self.loaded.pop(entry["name"], None)  # force re-verify on next use
            self.stubs[entry["name"]] = entry
        self.audit.append({"installed": pub, "sequence": body["sequence"]})
        return [e["name"] for e in body["tools"]]

    # --- deferred loading ----------------------------------------------
    def catalog(self) -> list[dict]:
        """What goes into the model's context up front: name + summary only."""
        return [
            {"name": e["name"], "summary": e["summary"]} for e in self.stubs.values()
        ]

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        return [
            s
            for s in self.catalog()
            if q in s["name"].lower() or q in s["summary"].lower()
        ]

    def load(self, name: str) -> dict:
        if name in self.loaded:
            return self.loaded[name]
        entry = self.stubs.get(name)
        if entry is None:
            self._refuse("unsigned_tool", f"{name} is not in any verified manifest")
        definition = self.fetch(name, entry["version"])
        if (
            definition.get("name") != name
            or definition.get("version") != entry["version"]
        ):
            self._refuse(
                "schema_drift",
                f"served {definition.get('name')}@{definition.get('version')}",
            )
        fp = fingerprint(definition)
        if fp != entry["fingerprint"]:
            self._refuse(
                "tampered",
                f"{name}: fingerprint {fp[:19]} != signed {entry['fingerprint'][:19]}",
            )
        self.loaded[name] = definition
        return definition

    def call(self, name: str, args: dict):
        definition = self.load(name)
        try:
            jsonschema.validate(args, definition["inputSchema"])
        except jsonschema.ValidationError as e:
            self._refuse("invalid_args", e.message)
        if name not in self.handlers:
            self._refuse("no_handler", name)
        return self.handlers[name](args)

    def context_bytes(self, deferred: bool = True) -> int:
        if deferred:
            return len(json.dumps(self.catalog()))
        return len(
            json.dumps(
                [self.fetch(e["name"], e["version"]) for e in self.stubs.values()]
            )
        )
