"""Core breach-aggregation engine for BREACHWATCH.

No network. All inputs are local files you control:

  * HIBP breach catalog JSON (the public ``breaches`` schema, a list of objects
    with ``Name``, ``Domain``, ``BreachDate``, ``DataClasses``, ``IsVerified``,
    ``IsSensitive`` ...). Account-to-breach membership is supplied separately as
    a simple ``{email: [BreachName, ...]}`` map, since membership requires the
    paid HIBP API. This keeps the tool offline and deterministic.
  * DeHashed-style JSON dumps: ``{"entries": [{email, username, password,
    hashed_password, database_name, ...}]}``.
  * Raw stealer-log credential lines, e.g. ``https://site/login:user@x.com:pw``
    or ``user@x.com:pw`` — the canonical infostealer ``URL:LOGIN:PASS`` format.

The engine normalizes everything into :class:`Exposure` records, dedupes,
correlates against the identities you own, and produces a risk-scored triage
report with concrete next actions.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Data classes that meaningfully raise the blast radius of a breach.
_HIGH_RISK_CLASSES = {
    "passwords",
    "password hints",
    "security questions and answers",
    "credit cards",
    "bank account numbers",
    "social security numbers",
    "government issued ids",
    "auth tokens",
    "partial credit card data",
    "historical passwords",
}
_MED_RISK_CLASSES = {
    "phone numbers",
    "physical addresses",
    "dates of birth",
    "geographic locations",
    "ip addresses",
    "private messages",
    "recovery email addresses",
}

# Source weights: a live plaintext password from a stealer log is worse than a
# years-old salted-hash dump.
_SOURCE_WEIGHT = {"stealer_log": 5, "dehashed": 3, "hibp": 2}

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def redact(secret: str) -> str:
    """Redact a password/token for safe display: keep length signal, hide value."""
    if not secret:
        return ""
    n = len(secret)
    if n <= 2:
        return "*" * n
    return f"{secret[0]}{'*' * (n - 2)}{secret[-1]} (len={n})"


def _norm_email(value: str) -> str:
    return (value or "").strip().lower()


@dataclass
class Identity:
    """An identity you own and want monitored."""

    email: str
    usernames: list[str] = field(default_factory=list)

    def matches(self, *, email: str = "", username: str = "") -> bool:
        if email and _norm_email(email) == _norm_email(self.email):
            return True
        if username:
            u = username.strip().lower()
            return any(u == x.strip().lower() for x in self.usernames)
        return False


@dataclass
class Exposure:
    """A single normalized exposure of one identity in one source."""

    identity: str
    source: str  # hibp | dehashed | stealer_log
    breach: str
    breach_date: str = ""
    data_classes: list[str] = field(default_factory=list)
    has_plaintext_password: bool = False
    has_hashed_password: bool = False
    password_redacted: str = ""
    origin_url: str = ""
    verified: bool = True
    severity: str = "info"
    score: int = 0

    def dedupe_key(self) -> tuple:
        return (self.identity, self.source, self.breach.lower(), self.origin_url)

    def to_dict(self) -> dict:
        return asdict(self)


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def _score_exposure(exp: Exposure) -> int:
    score = _SOURCE_WEIGHT.get(exp.source, 1) * 4
    classes = {c.strip().lower() for c in exp.data_classes}
    score += 12 * len(classes & _HIGH_RISK_CLASSES)
    score += 5 * len(classes & _MED_RISK_CLASSES)
    if exp.has_plaintext_password:
        score += 35
    elif exp.has_hashed_password:
        score += 10
    if not exp.verified:
        score -= 5
    # Recency: breaches in the last ~2 years hit harder.
    if exp.breach_date:
        try:
            bd = datetime.strptime(exp.breach_date[:10], "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            age_days = (datetime.now(timezone.utc) - bd).days
            if age_days <= 730:
                score += 10
            elif age_days <= 1825:
                score += 4
        except ValueError:
            pass
    return max(0, score)


def _finalize(exp: Exposure) -> Exposure:
    exp.score = _score_exposure(exp)
    exp.severity = severity_for(exp.score)
    return exp


def parse_hibp(
    catalog: list[dict], account_breaches: dict[str, list[str]]
) -> list[Exposure]:
    """Map HIBP breach catalog + per-account membership into exposures."""
    by_name = {str(b.get("Name", "")).lower(): b for b in catalog}
    out: list[Exposure] = []
    for email, names in (account_breaches or {}).items():
        for name in names:
            meta = by_name.get(str(name).lower(), {})
            classes = [str(c) for c in meta.get("DataClasses", [])]
            has_pw = any("password" in c.lower() for c in classes)
            out.append(
                _finalize(
                    Exposure(
                        identity=_norm_email(email),
                        source="hibp",
                        breach=meta.get("Name", name),
                        breach_date=str(meta.get("BreachDate", "")),
                        data_classes=classes,
                        has_hashed_password=has_pw,
                        verified=bool(meta.get("IsVerified", True)),
                    )
                )
            )
    return out


def parse_dehashed(dump: dict, identities: list[Identity]) -> list[Exposure]:
    """Map a DeHashed-style entries dump into exposures for owned identities."""
    out: list[Exposure] = []
    for entry in dump.get("entries", []):
        email = _norm_email(entry.get("email", ""))
        username = str(entry.get("username", "")).strip()
        owner = _match_identity(identities, email=email, username=username)
        if owner is None:
            continue
        plain = str(entry.get("password", "") or "")
        hashed = str(entry.get("hashed_password", "") or "")
        classes = ["Email addresses"]
        if plain or hashed:
            classes.append("Passwords")
        if entry.get("phone"):
            classes.append("Phone numbers")
        if entry.get("address"):
            classes.append("Physical addresses")
        out.append(
            _finalize(
                Exposure(
                    identity=owner.email,
                    source="dehashed",
                    breach=str(entry.get("database_name", "unknown")),
                    data_classes=classes,
                    has_plaintext_password=bool(plain),
                    has_hashed_password=bool(hashed) and not plain,
                    password_redacted=redact(plain) if plain else "",
                )
            )
        )
    return out


def parse_stealer_log(lines: Iterable[str], identities: list[Identity]) -> list[Exposure]:
    """Parse raw infostealer credential lines (URL:LOGIN:PASS or LOGIN:PASS)."""
    out: list[Exposure] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        url, login, password = _split_stealer_line(line)
        if not login or not password:
            continue
        email = login if _EMAIL_RE.match(login) else ""
        owner = _match_identity(identities, email=email, username=login)
        if owner is None:
            continue
        out.append(
            _finalize(
                Exposure(
                    identity=owner.email,
                    source="stealer_log",
                    breach=_domain_of(url) or "stealer-log",
                    data_classes=["Email addresses", "Passwords"],
                    has_plaintext_password=True,
                    password_redacted=redact(password),
                    origin_url=url,
                    breach_date=_now_iso()[:10],
                )
            )
        )
    return out


def _split_stealer_line(line: str) -> tuple[str, str, str]:
    # Canonical stealer format is URL:LOGIN:PASS, but URLs contain ':' (scheme,
    # port). Detect a leading URL and split the remainder as LOGIN:PASS.
    url = ""
    rest = line
    m = re.match(r"^(https?://[^\s]+?)[:|](.*)$", line)
    if m:
        url, rest = m.group(1), m.group(2)
    # rest is LOGIN:PASS — split on the first separator only (passwords may hold ':').
    parts = re.split(r"[:|]", rest, maxsplit=1)
    if len(parts) != 2:
        return url, "", ""
    return url, parts[0].strip(), parts[1].strip()


def _domain_of(url: str) -> str:
    if not url:
        return ""
    m = re.match(r"^https?://([^/:?#]+)", url)
    return m.group(1).lower() if m else ""


def _match_identity(
    identities: list[Identity], *, email: str = "", username: str = ""
) -> Identity | None:
    for ident in identities:
        if ident.matches(email=email, username=username):
            return ident
    return None


def _dedupe(exposures: list[Exposure]) -> list[Exposure]:
    """Drop duplicate exposures, keeping the highest-scoring instance."""
    best: dict[tuple, Exposure] = {}
    for exp in exposures:
        key = exp.dedupe_key()
        cur = best.get(key)
        if cur is None or exp.score > cur.score:
            best[key] = exp
    return sorted(best.values(), key=lambda e: e.score, reverse=True)


@dataclass
class TriageReport:
    generated_at: str
    identities: list[str]
    exposures: list[Exposure]
    summary: dict
    actions: list[str]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["exposures"] = [e.to_dict() for e in self.exposures]
        return d


def _build_actions(exposures: list[Exposure]) -> list[str]:
    actions: list[str] = []
    plaintext = {e.identity for e in exposures if e.has_plaintext_password}
    for email in sorted(plaintext):
        actions.append(
            f"URGENT: rotate password + enable MFA for {email} "
            "(plaintext credential found)."
        )
    domains = sorted(
        {e.breach for e in exposures if e.source == "stealer_log" and e.breach}
    )
    if domains:
        actions.append(
            "Infostealer infection likely — audit the device and rotate creds for: "
            + ", ".join(domains[:10])
        )
    if any(e.severity in ("high", "critical") for e in exposures):
        actions.append(
            "Review password reuse across high-severity breaches; assume reused "
            "passwords are compromised everywhere."
        )
    if not actions:
        actions.append("No urgent actions. Keep monitoring and use unique passwords + MFA.")
    return actions


def triage(
    identities: list[Identity],
    *,
    hibp_catalog: list[dict] | None = None,
    hibp_accounts: dict[str, list[str]] | None = None,
    dehashed: dict | None = None,
    stealer_lines: Iterable[str] | None = None,
) -> TriageReport:
    """Aggregate every source into a single deduped, risk-scored triage report."""
    exposures: list[Exposure] = []
    if hibp_catalog is not None or hibp_accounts:
        exposures += parse_hibp(hibp_catalog or [], hibp_accounts or {})
    if dehashed is not None:
        exposures += parse_dehashed(dehashed, identities)
    if stealer_lines is not None:
        exposures += parse_stealer_log(stealer_lines, identities)

    exposures = _dedupe(exposures)

    by_sev = {s: 0 for s in SEVERITY_ORDER}
    for e in exposures:
        by_sev[e.severity] += 1
    summary = {
        "total_exposures": len(exposures),
        "by_severity": by_sev,
        "plaintext_passwords": sum(1 for e in exposures if e.has_plaintext_password),
        "affected_identities": len({e.identity for e in exposures}),
        "max_score": max((e.score for e in exposures), default=0),
    }
    return TriageReport(
        generated_at=_now_iso(),
        identities=[i.email for i in identities],
        exposures=exposures,
        summary=summary,
        actions=_build_actions(exposures),
    )


def load_sources(config_path: str | Path) -> tuple[list[Identity], dict]:
    """Load a JSON config describing identities + source files.

    Schema::

        {
          "identities": [{"email": "...", "usernames": ["..."]}],
          "hibp_catalog": "path.json",
          "hibp_accounts": "path.json",   # {email: [BreachName,...]}
          "dehashed": "path.json",
          "stealer_log": "path.txt"
        }

    Returns ``(identities, sources)`` where ``sources`` is ready to splat into
    :func:`triage` as keyword arguments.
    """
    config_path = Path(config_path)
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    base = config_path.parent

    identities = [
        Identity(email=_norm_email(i["email"]), usernames=list(i.get("usernames", [])))
        for i in cfg.get("identities", [])
    ]
    if not identities:
        raise ValueError("config must define at least one identity")

    def _read_json(key: str):
        rel = cfg.get(key)
        if not rel:
            return None
        return json.loads((base / rel).read_text(encoding="utf-8"))

    sources: dict = {}
    cat = _read_json("hibp_catalog")
    if cat is not None:
        sources["hibp_catalog"] = cat
    acc = _read_json("hibp_accounts")
    if acc is not None:
        sources["hibp_accounts"] = acc
    deh = _read_json("dehashed")
    if deh is not None:
        sources["dehashed"] = deh
    if cfg.get("stealer_log"):
        text = (base / cfg["stealer_log"]).read_text(encoding="utf-8")
        sources["stealer_lines"] = text.splitlines()
    return identities, sources
