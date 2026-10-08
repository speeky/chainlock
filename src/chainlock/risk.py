"""Supply-chain risk scoring and typosquat detection."""

from __future__ import annotations

from .parsers import Dependency

# Hand-curated shortlist of the most-imitated package names on PyPI and npm.
POPULAR_PYPI = {
    "requests", "urllib3", "flask", "django", "numpy", "pandas", "pillow",
    "sqlalchemy", "pyyaml", "click", "boto3", "botocore", "cryptography",
    "pytest", "setuptools", "pip", "wheel", "jinja2", "certifi", "idna",
    "tqdm", "openai", "anthropic", "langchain", "httpx", "rich", "typer",
}
POPULAR_NPM = {
    "react", "react-dom", "express", "lodash", "axios", "typescript",
    "next", "vue", "chalk", "commander", "fs-extra", "postcss", "tailwindcss",
    "esbuild", "vite", "eslint", "prettier", "ws", "node-fetch", "cross-env",
    "dotenv", "jest", "webpack", "rollup", "uuid", "zod", "openai",
}


def levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3  # early exit: anything > 2 is out of scope anyway
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def detect_typosquats(deps: list[Dependency]) -> None:
    for dep in deps:
        pool = POPULAR_PYPI if dep.ecosystem == "PyPI" else (
            POPULAR_NPM if dep.ecosystem == "npm" else set()
        )
        for popular in pool:
            if dep.name.lower() == popular:
                break
            d = levenshtein(dep.name.lower(), popular)
            if 1 <= d <= 2 and abs(len(dep.name) - len(popular)) <= 1:
                dep.typosquat_of = popular
                break


def risk_score(dep: Dependency) -> int:
    """0-100 supply-chain risk score for a single dependency."""
    score = 0
    for vuln in dep.vulnerabilities:
        cvss = vuln.get("cvss") or 5.0
        if vuln.get("fixed"):
            cvss *= 0.8  # a published fix softens the finding
        score += int(cvss * 4)  # CVSS 9.x critical -> ~30 pts each
    score = min(score, 60)
    if dep.typosquat_of:
        score += 35
    if not dep.pinned:
        score += 15
    return min(score, 100)


def grade(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"
