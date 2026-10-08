<div align="center">

# 🔗 Chainlock

**Supply-chain security for your dependencies.**

Scan your lockfiles against the OSV vulnerability database, score supply-chain
risk per dependency, catch typosquats, and export a CycloneDX SBOM —
in one zero-dependency CLI.

[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](https://www.python.org)
[![Data: OSV](https://img.shields.io/badge/data-OSV.dev-47b3f5.svg)](https://osv.dev)

`pip install chainlock-cli` · [chainlock.dev](https://chainlock.dev) · Cloud early access → **hello@chainlock.dev**

</div>

---

## Why

Your app is only as trustworthy as your dependency tree. Most teams find out
about a compromised transitive package days after it ships. Chainlock makes
that check a one-liner — locally and in CI — with **zero dependencies of its
own**, so the tool auditing your supply chain never adds to it.

## Quickstart

```bash
pip install chainlock-cli

# Python projects
chainlock scan requirements.txt

# Node projects
chainlock scan package-lock.json

# Go projects
chainlock scan go.sum
```

```text
$ chainlock scan requirements.txt

chainlock scan · requirements.txt

  RISK      PACKAGE                             VERSION      FINDINGS
  --------- ---------------------------------- ------------ ------------------------------
  CRITICAL  requests                            2.19.0       2 CVE/advisory GHSA-... (+1)
  HIGH      reqeusts                            1.2.3        typosquat of 'requests'
  MEDIUM    flask                               -            unpinned version
  LOW       rich                                13.7.0       clean

Summary: 4 deps · 2 vulnerable · grades: 1C / 1H / 1M / 1L
Data: OSV (osv.dev) · Chainlock v0.3.0
```

Exit code is non-zero when any dependency grades HIGH or CRITICAL —
drop it straight into CI:

```yaml
# .github/workflows/chainlock.yml
- run: pip install chainlock-cli && chainlock scan requirements.txt
```

## What it checks

| Check | How |
|---|---|
| Known vulnerabilities | Batch query against the [OSV](https://osv.dev) database (PyPI, npm, Go) |
| Severity & fix status | Advisory details with CVSS-based weighting, softened when a fix is published |
| Typosquatting | Edit distance against curated lists of the most-imitated package names |
| Version pinning | Unpinned (`>=`, URL/VCS) requirements inflate risk |
| SBOM export | `--sbom sbom.json` emits CycloneDX 1.5 |

## Chainlock Cloud *(early access)*

The CLI is and stays open source (MIT). We're building the hosted layer on
top of it:

- **Org dashboard** — every repo and CI run in one place, with diff-aware alerts
- **Policy engine** — block typosquats, unreviewed maintainers, or license drift at PR time
- **Continuous monitoring** — re-alert when a *new* advisory lands on a version you already shipped

Request early access: **hello@chainlock.dev**

## Development

```bash
git clone https://github.com/speeky/chainlock
cd chainlock
pip install -e .
python -m pytest tests/ -q
```

Pure stdlib — no runtime dependencies, no build-time dependencies beyond setuptools.

## Roadmap

- [x] OSV scanning for requirements.txt / package-lock.json / go.sum
- [x] Typosquat heuristics + risk scoring
- [x] CycloneDX SBOM export
- [ ] `--sarif` output for GitHub code scanning
- [ ] poetry.lock / Cargo.lock / go.mod support
- [ ] Offline cache of advisories

## License

[MIT](LICENSE) — © 2026 Chainlock contributors
