"""Offline unit tests for parsers, typosquat detection and risk scoring."""

import json

from chainlock.parsers import (
    parse_go_sum,
    parse_lockfile,
    parse_package_lock,
    parse_requirements,
)
from chainlock.risk import detect_typosquats, grade, levenshtein, risk_score
from chainlock.parsers import Dependency

REQS = """
# core
requests==2.31.0
flask>=2.0
urllib3==1.26.4 ; python_version < '3.10'
reqeusts==1.2.3
-r base.txt
git+https://github.com/psf/requests.git#egg=requests
"""

LOCK_V3 = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2", "dev": False},
            "node_modules/chalk": {"version": "5.3.0", "dev": True},
        },
    }
)

GO_SUM = """
github.com/pkg/errors v0.9.1 h1:FEBLx1zQ2144hpz9nQpRmAEHJcH5C1Jo7s0MpmBwUq8=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/sys v0.13.0 h1:FooBar=
"""


def test_parse_requirements():
    deps = parse_requirements(REQS)
    names = [d.name for d in deps]
    assert "requests" in names and "flask" in names and "reqeusts" in names
    by_name = {d.name: d for d in deps}
    assert by_name["requests"].pinned is True
    assert by_name["requests"].version == "2.31.0"
    assert by_name["flask"].pinned is False
    # env marker stripped; include-lines and VCS refs are skipped entirely
    assert by_name["urllib3"].version == "1.26.4"
    assert not any("git+" in name or ".git" in name for name in names)
    assert "base.txt" not in names


def test_parse_package_lock_v3():
    deps = parse_package_lock(LOCK_V3)
    by_name = {d.name: d for d in deps}
    assert by_name["express"].version == "4.18.2"
    assert by_name["express"].ecosystem == "npm"
    assert by_name["express"].pinned is True
    assert by_name["chalk"].dev is True
    assert "" not in by_name  # root package excluded


def test_parse_go_sum():
    deps = parse_go_sum(GO_SUM)
    keys = {(d.name, d.version) for d in deps}
    assert ("github.com/pkg/errors", "v0.9.1") in keys
    assert ("golang.org/x/sys", "v0.13.0") in keys
    assert len([k for k in keys if k[0] == "github.com/pkg/errors"]) == 1  # /go.mod line skipped


def test_typosquat_detection():
    deps = [
        Dependency("reqeusts", "1.2.3", "PyPI"),
        Dependency("requests", "2.31.0", "PyPI"),
        Dependency("lodahs", "4.0.0", "npm"),
        Dependency("totally-unrelated-name", "1.0.0", "PyPI"),
    ]
    detect_typosquats(deps)
    assert deps[0].typosquat_of == "requests"
    assert deps[1].typosquat_of is None
    assert deps[2].typosquat_of == "lodash"
    assert deps[3].typosquat_of is None


def test_levenshtein():
    assert levenshtein("requests", "requests") == 0
    assert levenshtein("reqeusts", "requests") == 2
    assert levenshtein("abc", "xyz") == 3


def test_risk_scoring():
    clean = Dependency("requests", "2.31.0", "PyPI", pinned=True)
    assert risk_score(clean) == 0 and grade(0) == "LOW"

    vulnerable = Dependency("foo", "1.0", "PyPI", pinned=True)
    vulnerable.vulnerabilities = [
        {"id": "GHSA-xxxx", "cvss": 9.1, "fixed": True},
        {"id": "GHSA-yyyy", "cvss": 7.5, "fixed": False},
    ]
    score = risk_score(vulnerable)
    assert 40 <= score < 100 and grade(score) in ("HIGH", "CRITICAL")

    typosquat = Dependency("reqeusts", "1.0", "PyPI", pinned=False)
    typosquat.typosquat_of = "requests"
    assert risk_score(typosquat) >= 50  # 35 typosquat + 15 unpinned


def test_unsupported_lockfile(tmp_path):
    bad = tmp_path / "poetry.lock"
    bad.write_text("")
    try:
        parse_lockfile(bad)
        raise AssertionError("should have raised")
    except ValueError as exc:
        assert "Unsupported lockfile" in str(exc)
