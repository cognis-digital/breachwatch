"""BREACHWATCH — personal breach aggregator (HIBP + DeHashed + stealer-log triage).

Standard library only. Zero install. No network calls in the core engine — it
operates on local exports you already have (HIBP breach catalogs, DeHashed JSON
dumps, raw stealer-log credential dumps). The engine normalizes, dedupes,
correlates, and risk-scores breach exposures for a set of identities you own.
"""
from .core import (
    Exposure,
    Identity,
    TriageReport,
    load_sources,
    parse_hibp,
    parse_dehashed,
    parse_stealer_log,
    triage,
    redact,
    severity_for,
)

TOOL_NAME = "breachwatch"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Exposure",
    "Identity",
    "TriageReport",
    "load_sources",
    "parse_hibp",
    "parse_dehashed",
    "parse_stealer_log",
    "triage",
    "redact",
    "severity_for",
]
