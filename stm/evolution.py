"""Schema evolution: classify a change between two tool input schemas.

Rule of thumb for *input* schemas: a change is compatible when every argument object that was
valid under the old schema is still valid under the new one (old callers keep working).
"""

from __future__ import annotations

from dataclasses import dataclass

BREAKING, COMPATIBLE, NONE = "breaking", "compatible", "none"

_WIDENS = {("integer", "number")}


@dataclass
class Change:
    kind: str  # BREAKING | COMPATIBLE
    path: str
    detail: str


def _types(s: dict) -> set[str]:
    t = s.get("type")
    if t is None:
        return set()
    return {t} if isinstance(t, str) else set(t)


def _compare(old: dict, new: dict, path: str, out: list[Change]) -> None:
    ot, nt = _types(old), _types(new)
    if ot != nt:
        if (
            nt
            and not ot <= nt
            and not all((a, b) in _WIDENS for a in ot - nt for b in nt)
        ):
            out.append(Change(BREAKING, path, f"type {sorted(ot)} -> {sorted(nt)}"))
        else:
            out.append(
                Change(COMPATIBLE, path, f"type widened {sorted(ot)} -> {sorted(nt)}")
            )
    if "enum" in old or "enum" in new:
        oe, ne = set(map(repr, old.get("enum", []))), set(
            map(repr, new.get("enum", []))
        )
        if "enum" not in old:
            out.append(Change(BREAKING, path, "enum added"))
        elif "enum" in new and not oe <= ne:
            out.append(
                Change(BREAKING, path, f"enum values removed: {sorted(oe - ne)}")
            )
        elif ne != oe:
            out.append(Change(COMPATIBLE, path, "enum widened"))
    for key, tighter in (
        ("maxLength", lambda o, n: n < o),
        ("maximum", lambda o, n: n < o),
        ("minLength", lambda o, n: n > o),
        ("minimum", lambda o, n: n > o),
    ):
        o, n = old.get(key), new.get(key)
        if o is None and n is not None:
            out.append(Change(BREAKING, path, f"{key} added"))
        elif o is not None and n is not None and tighter(o, n):
            out.append(Change(BREAKING, path, f"{key} tightened {o} -> {n}"))
        elif o is not None and n != o:
            out.append(Change(COMPATIBLE, path, f"{key} relaxed"))
    if old.get("pattern") != new.get("pattern"):
        kind = COMPATIBLE if new.get("pattern") is None else BREAKING
        out.append(Change(kind, path, "pattern changed"))

    oprops, nprops = old.get("properties", {}), new.get("properties", {})
    oreq, nreq = set(old.get("required", [])), set(new.get("required", []))
    closed = new.get("additionalProperties") is False
    for name in oprops.keys() - nprops.keys():
        out.append(
            Change(
                BREAKING if closed or name in oreq else COMPATIBLE,
                f"{path}.{name}",
                "property removed",
            )
        )
    for name in nprops.keys() - oprops.keys():
        out.append(
            Change(
                BREAKING if name in nreq else COMPATIBLE,
                f"{path}.{name}",
                (
                    "required property added"
                    if name in nreq
                    else "optional property added"
                ),
            )
        )
    for name in nreq - oreq:
        if name in oprops:
            out.append(Change(BREAKING, f"{path}.{name}", "property became required"))
    for name in oreq - nreq:
        out.append(Change(COMPATIBLE, f"{path}.{name}", "property became optional"))
    if old.get("additionalProperties") is not False and closed:
        out.append(Change(BREAKING, path, "additionalProperties closed"))
    for name in oprops.keys() & nprops.keys():
        _compare(oprops[name], nprops[name], f"{path}.{name}", out)
    if "items" in old and "items" in new:
        _compare(old["items"], new["items"], f"{path}[]", out)


def diff(old: dict, new: dict) -> list[Change]:
    out: list[Change] = []
    _compare(old, new, "$", out)
    return out


def classify(old: dict, new: dict) -> str:
    changes = diff(old, new)
    if any(c.kind == BREAKING for c in changes):
        return BREAKING
    return COMPATIBLE if changes else NONE


def parse_semver(v: str) -> tuple[int, int, int]:
    a, b, c = v.split(".")
    return int(a), int(b), int(c)


def required_bump(
    old_version: str, new_version: str, change: str, description_changed: bool = False
) -> str | None:
    """Return an error string if the version bump does not match the change, else None."""
    o, n = parse_semver(old_version), parse_semver(new_version)
    if n <= o:
        return f"version must increase ({old_version} -> {new_version})"
    if change == BREAKING and n[0] == o[0]:
        return "breaking schema change requires a major version bump"
    if change == COMPATIBLE and n[:2] == o[:2]:
        return "schema change requires at least a minor version bump"
    if description_changed and n[:2] == o[:2]:
        return "description change requires at least a minor version bump"
    return None
