"""Lockfile parsers. Each parser returns a list of Dependency."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<operator>[=<>~!]=?|===)?\s*(?P<version>[^\s;#]+)?"
)


@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str  # PyPI | npm | Go
    pinned: bool = False
    source: str = ""
    dev: bool = False
    vulnerabilities: list[dict] = field(default_factory=list)
    typosquat_of: str | None = None

    @property
    def key(self) -> tuple[str, str | None]:
        return (self.name.lower(), self.version)


def parse_requirements(text: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http", "#")):
            continue
        line = line.split(";", 1)[0].strip()  # drop env markers
        if "@" in line:  # direct URL / VCS reference: unpinned target
            name = line.split("@", 1)[0].strip()
            deps.append(Dependency(name, None, "PyPI", pinned=False, source="requirements.txt"))
            continue
        m = REQ_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        version = m.group("version")
        op = m.group("operator") or ""
        pinned = op == "==" and version is not None
        deps.append(
            Dependency(name, version, "PyPI", pinned=pinned, source="requirements.txt")
        )
    return deps


def parse_package_lock(text: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    packages = data.get("packages")
    if packages:  # lockfileVersion 2/3
        for key, meta in packages.items():
            if not key.startswith("node_modules/"):
                continue
            name = key[len("node_modules/"):]
            if not name or "version" not in meta:
                continue
            deps.append(
                Dependency(
                    name,
                    meta["version"],
                    "npm",
                    pinned=True,  # a lockfile always pins
                    source="package-lock.json",
                    dev=bool(meta.get("dev", False)),
                )
            )
    else:  # lockfileVersion 1
        for name, meta in data.get("dependencies", {}).items():
            deps.append(
                Dependency(name, meta.get("version"), "npm", pinned=True,
                           source="package-lock.json", dev=bool(meta.get("dev", False)))
            )
    return deps


def parse_go_sum(text: str) -> list[Dependency]:
    seen: set[tuple[str, str]] = set()
    deps: list[Dependency] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        if version.endswith("/go.mod"):  # module hash line, not a pinned build
            continue
        key = (module, version)
        if key not in seen:
            seen.add(key)
            deps.append(Dependency(module, version, "Go", pinned=True, source="go.sum"))
    return deps


PARSERS = {
    "requirements.txt": parse_requirements,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "go.sum": parse_go_sum,
}


def parse_lockfile(path: str | Path) -> list[Dependency]:
    path = Path(path)
    name = path.name
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        parser = parse_package_lock
    elif name == "go.sum":
        parser = parse_go_sum
    elif name == "requirements.txt" or (
        path.suffix == ".txt" and "requirements" in name
    ):
        parser = parse_requirements
    else:
        raise ValueError(
            f"Unsupported lockfile: {name}. "
            "Supported: requirements.txt, package-lock.json, go.sum"
        )
    return parser(path.read_text(encoding="utf-8"))
