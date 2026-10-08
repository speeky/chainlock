"""Minimal OSV API v1 client (https://api.osv.dev) built on stdlib only."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from .parsers import Dependency

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
TIMEOUT = 15


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "chainlock-cli"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "chainlock-cli"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def fetch_vulnerabilities(deps: list[Dependency], max_details: int = 25) -> None:
    """Populate dep.vulnerabilities in place using the OSV batch endpoint,
    then hydrate the most severe-looking entries with CVSS details."""
    queries = [
        {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
        for d in deps
    ]
    results = _post(OSV_BATCH_URL, {"queries": queries}).get("results", [])

    hydrated = 0
    for dep, result in zip(deps, results):
        ids = [v["id"] for v in result.get("vulns", [])]
        for vuln_id in ids:
            entry = {"id": vuln_id}
            if hydrated < max_details:
                try:
                    detail = _get(OSV_VULN_URL.format(vuln_id))
                    entry["summary"] = detail.get("summary", "")
                    entry["cvss"] = _max_cvss(detail)
                    entry["fixed"] = _has_fix(detail, dep)
                    hydrated += 1
                except (urllib.error.URLError, urllib.error.HTTPError):
                    pass
            dep.vulnerabilities.append(entry)


def _max_cvss(vuln: dict) -> float | None:
    """Best-effort severity score from an OSV record (GitHub advisories carry
    labels in database_specific rather than numeric CVSS base scores)."""
    scores = []
    ds = vuln.get("database_specific", {})
    label = ds.get("severity") or ds.get("severity_rating")
    if isinstance(label, str):
        scores.append(_label_to_score(label.lower()))
    return max(scores) if scores else None


_LABELS = {
    "critical": 9.0,
    "high": 7.5,
    "moderate": 5.0,
    "medium": 5.0,
    "low": 2.5,
}


def _label_to_score(label: str) -> float:
    for key, value in _LABELS.items():
        if key in label:
            return value
    return 5.0


def _has_fix(vuln: dict, dep: Dependency) -> bool:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() == dep.name.lower():
            for rng in affected.get("ranges", []):
                if any(e.get("fixed") for e in rng.get("events", [])):
                    return True
    return False
