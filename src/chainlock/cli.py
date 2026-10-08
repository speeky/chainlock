"""chainlock CLI entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .osv_client import fetch_vulnerabilities
from .parsers import Dependency, parse_lockfile
from .risk import detect_typosquats, grade, risk_score

RESET, BOLD, RED, YELLOW, GREEN, CYAN, DIM = (
    "\033[0m", "\033[1m", "\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[2m",
)
GRADE_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}


def _enable_ansi() -> None:
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)


def scan(path: str, as_json: bool, sbom_path: str | None, max_details: int) -> int:
    try:
        deps = parse_lockfile(path)
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"{RED}error:{RESET} {exc}", file=sys.stderr)
        return 2
    if not deps:
        print(f"{YELLOW}warning:{RESET} no dependencies found in {path}", file=sys.stderr)
        return 0

    print(f"{DIM}Querying OSV database for {len(deps)} dependencies...{RESET}",
          file=sys.stderr)
    fetch_vulnerabilities(deps, max_details=max_details)
    detect_typosquats(deps)

    for dep in deps:
        dep_score = risk_score(dep)
        dep.__dict__["score"] = dep_score
        dep.__dict__["grade"] = grade(dep_score)

    if as_json:
        print(json.dumps(report(path, deps), indent=2))
    else:
        render_table(path, deps)

    if sbom_path:
        Path(sbom_path).write_text(
            json.dumps(cyclonedx(path, deps), indent=2), encoding="utf-8"
        )
        print(f"{DIM}SBOM written to {sbom_path}{RESET}", file=sys.stderr)

    worst = max(d.__dict__["score"] for d in deps)
    return 1 if worst >= 40 else 0


def report(path: str, deps: list[Dependency]) -> dict:
    return {
        "tool": "chainlock",
        "version": __version__,
        "lockfile": path,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(deps),
        "dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "pinned": d.pinned,
                "risk_score": d.__dict__["score"],
                "risk_grade": d.__dict__["grade"],
                "typosquat_of": d.typosquat_of,
                "vulnerabilities": d.vulnerabilities,
            }
            for d in deps
        ],
    }


def summarize(deps: list[Dependency]) -> dict:
    return {
        "total": len(deps),
        "vulnerable": sum(1 for d in deps if d.vulnerabilities),
        "critical": sum(1 for d in deps if d.__dict__["grade"] == "CRITICAL"),
        "high": sum(1 for d in deps if d.__dict__["grade"] == "HIGH"),
        "medium": sum(1 for d in deps if d.__dict__["grade"] == "MEDIUM"),
        "low": sum(1 for d in deps if d.__dict__["grade"] == "LOW"),
    }


def render_table(path: str, deps: list[Dependency]) -> None:
    s = summarize(deps)
    print(f"\n{BOLD}chainlock scan{RESET} {DIM}· {path}{RESET}\n")
    print(f"  {'RISK':<9} {'PACKAGE':<34} {'VERSION':<12} FINDINGS")
    print(f"  {'-' * 9} {'-' * 34} {'-' * 12} {'-' * 30}")
    for d in sorted(deps, key=lambda x: -x.__dict__["score"]):
        g = d.__dict__["grade"]
        color = GRADE_COLOR[g]
        findings = []
        if d.vulnerabilities:
            ids = ", ".join(v["id"] for v in d.vulnerabilities[:3])
            more = "" if len(d.vulnerabilities) <= 3 else f" (+{len(d.vulnerabilities) - 3})"
            findings.append(f"{len(d.vulnerabilities)} CVE/advisory {DIM}{ids}{more}{RESET}")
        if d.typosquat_of:
            findings.append(f"{RED}typosquat of '{d.typosquat_of}'{RESET}")
        if not d.pinned:
            findings.append(f"{YELLOW}unpinned version{RESET}")
        print(
            f"  {color}{g:<9}{RESET} {d.name:<34.34} {d.version or '-':<12.12} "
            f"{'; '.join(findings) or GREEN + 'clean' + RESET}"
        )
    print(
        f"\n  {BOLD}Summary:{RESET} {len(deps)} deps · "
        f"{RED}{s['vulnerable']} vulnerable{RESET} · "
        f"grades: {s['critical']}C / {s['high']}H / {s['medium']}M / {s['low']}L"
    )
    print(f"  {DIM}Data: OSV (osv.dev) · Chainlock v{__version__}{RESET}\n")


def cyclonedx(path: str, deps: list[Dependency]) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "Chainlock", "name": "chainlock-cli", "version": __version__}],
        },
        "components": [
            {
                "type": "library",
                "name": d.name,
                "version": d.version or "",
                "purl": _purl(d),
            }
            for d in deps
        ],
    }


def _purl(d: Dependency) -> str:
    version = d.version or ""
    return {
        "PyPI": f"pkg:pypi/{d.name.lower()}@{version}",
        "npm": f"pkg:npm/{d.name}@{version}",
        "Go": f"pkg:golang/{d.name}@{version}",
    }[d.ecosystem]


def main(argv: list[str] | None = None) -> int:
    _enable_ansi()
    parser = argparse.ArgumentParser(
        prog="chainlock",
        description="Supply-chain security scanner for your dependencies.",
    )
    parser.add_argument("--version", action="version", version=f"chainlock {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a lockfile against the OSV database")
    p_scan.add_argument("lockfile", help="requirements.txt | package-lock.json | go.sum")
    p_scan.add_argument("--json", action="store_true", help="Output JSON instead of a table")
    p_scan.add_argument("--sbom", metavar="FILE", help="Also write a CycloneDX SBOM")
    p_scan.add_argument(
        "--max-details", type=int, default=25,
        help="Max advisory detail lookups (network calls), default: 25",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        return scan(args.lockfile, args.json, args.sbom, args.max_details)
    return 0


if __name__ == "__main__":
    sys.exit(main())
