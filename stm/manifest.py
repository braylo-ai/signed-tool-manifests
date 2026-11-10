"""Tool fingerprints and ed25519-signed manifests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


FINGERPRINT_FIELDS = (
    "name",
    "version",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
)


def fingerprint(tool: dict) -> str:
    """sha256 over name + version + description + schemas + annotations (canonical JSON)."""
    return (
        "sha256:"
        + hashlib.sha256(
            canonical({k: tool.get(k) for k in FINGERPRINT_FIELDS})
        ).hexdigest()
    )


def key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


class ManifestError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code = code


@dataclass
class TrustStore:
    """publisher -> {key_id: public key}; plus revoked key ids."""

    keys: dict[str, dict[str, Ed25519PublicKey]] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)

    def add(self, publisher: str, pub: Ed25519PublicKey) -> str:
        kid = key_id(pub)
        self.keys.setdefault(publisher, {})[kid] = pub
        return kid

    def revoke(self, kid: str) -> None:
        self.revoked.add(kid)


def build_manifest(
    publisher: str, tools: list[dict], sequence: int, issued_at: int, ttl: int = 86400
) -> dict:
    """Unsigned manifest body. Each entry carries its fingerprint; the full definition is
    stored alongside so a registry can serve stubs and load definitions lazily."""
    entries = [
        {
            "name": t["name"],
            "version": t["version"],
            "summary": t.get("summary") or t["description"][:80],
            "fingerprint": fingerprint(t),
        }
        for t in tools
    ]
    return {
        "publisher": publisher,
        "sequence": sequence,
        "issued_at": issued_at,
        "expires_at": issued_at + ttl,
        "tools": sorted(entries, key=lambda e: e["name"]),
    }


def sign(body: dict, priv: Ed25519PrivateKey) -> dict:
    sig = priv.sign(canonical(body))
    return {
        "body": body,
        "signature": {
            "alg": "ed25519",
            "kid": key_id(priv.public_key()),
            "value": base64.b64encode(sig).decode(),
        },
    }


def verify(signed: dict, trust: TrustStore, now: int) -> dict:
    """Return the manifest body if signature, key and expiry check out; raise ManifestError otherwise."""
    if (
        not isinstance(signed, dict)
        or "signature" not in signed
        or "body" not in signed
    ):
        raise ManifestError("unsigned", "manifest has no signature")
    body, sig = signed["body"], signed["signature"]
    if sig.get("alg") != "ed25519":
        raise ManifestError("bad_alg", str(sig.get("alg")))
    kid = sig.get("kid")
    if kid in trust.revoked:
        raise ManifestError("revoked_key", kid)
    pub = trust.keys.get(body.get("publisher"), {}).get(kid)
    if pub is None:
        raise ManifestError(
            "unknown_key", f"{kid} is not trusted for publisher {body.get('publisher')}"
        )
    try:
        pub.verify(base64.b64decode(sig["value"]), canonical(body))
    except (InvalidSignature, ValueError) as exc:
        raise ManifestError(
            "bad_signature", "signature does not match manifest body"
        ) from exc
    if now >= body["expires_at"]:
        raise ManifestError("expired", f"expired at {body['expires_at']}")
    return body
