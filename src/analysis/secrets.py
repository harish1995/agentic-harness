"""Regex-based hardcoded-secret scanning over decompiled source and config text.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts (Pattern
table + Redaction rule). Copied verbatim from the spec; do not change a
pattern without updating the spec first.
"""

import re
from pathlib import Path
from typing import NamedTuple, TypedDict


class SecretFinding(TypedDict):
    pattern_name: str
    file_path: str
    line_number: int
    matched_text_redacted: str
    confidence: str


class _Pattern(NamedTuple):
    name: str
    regex: "re.Pattern[str]"
    confidence: str


# Verbatim from spec/agent.md -> Internal Module Contracts -> src/analysis/secrets.py
_PATTERNS: list[_Pattern] = [
    _Pattern("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "High"),
    _Pattern(
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,20}?(?:secret|access)?_?key.{0,20}?['\"](?P<secret>[0-9a-zA-Z/+]{40})['\"]"),
        "High",
    ),
    _Pattern(
        "Generic API Key",
        re.compile(r"(?i)(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-]{16,})['\"]"),
        "Medium",
    ),
    _Pattern(
        "Private Key Block",
        re.compile(r"-----BEGIN ((RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY-----"),
        "High",
    ),
    _Pattern(
        "JDBC Creds in URL",
        re.compile(r"jdbc:[a-z]+://[^\"'\s]*:[^\"'\s]*@[^\"'\s]+"),
        "High",
    ),
    _Pattern(
        "Generic DB Creds in URL",
        re.compile(r"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql)://[^:\s]+:[^@\s]+@[^\s'\"]+"),
        "High",
    ),
    _Pattern(
        "JWT / Generic Secret Key",
        re.compile(r"(?i)(?:jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"](?P<secret>[^'\"]{8,})['\"]"),
        "Medium",
    ),
    _Pattern(
        "Hardcoded Password",
        re.compile(r"(?i)password\s*[:=]\s*['\"](?P<secret>[^'\"]{4,})['\"]"),
        "Low",
    ),
    _Pattern("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"), "High"),
    _Pattern("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "High"),
    _Pattern("GitHub Token", re.compile(r"ghp_[0-9A-Za-z]{36}"), "High"),
]


def _redact(matched_text: str) -> str:
    """First 4 + last 4 characters of the matched value, middle replaced with
    '…' — the raw full secret is never returned in full."""
    if len(matched_text) <= 8:
        return "…" if len(matched_text) <= 2 else f"{matched_text[:2]}…"
    return f"{matched_text[:4]}…{matched_text[-4:]}"


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def _secret_text(match: "re.Match[str]") -> str:
    """The actual secret value to redact. Patterns whose match wraps the
    secret in a keyword+syntax prefix/suffix (e.g. `password = "..."`)
    capture it in a named `secret` group so only the real value — never the
    surrounding keyword/syntax — is passed to `_redact`. Patterns where the
    whole match IS the secret (or the secret is fully swallowed by the
    redaction's own `…` truncation) have no such group and fall back to the
    full match."""
    groups = match.groupdict()
    if "secret" in groups and groups["secret"] is not None:
        return groups["secret"]
    return match.group(0)


def _scan_text(text: str, file_path: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for pattern in _PATTERNS:
        for match in pattern.regex.finditer(text):
            line_number = text.count("\n", 0, match.start()) + 1
            findings.append(
                SecretFinding(
                    pattern_name=pattern.name,
                    file_path=file_path,
                    line_number=line_number,
                    matched_text_redacted=_redact(_secret_text(match)),
                    confidence=pattern.confidence,
                )
            )
    return findings


def scan_secrets(decompiled_dirs: list[str], config_file_paths: dict[str, str]) -> list[SecretFinding]:
    """Apply the fixed regex pattern table to every file under each decompiled
    dir (walked recursively) and every config file's text. Unreadable/binary
    files are skipped rather than raising.
    """
    findings: list[SecretFinding] = []

    for dir_path in decompiled_dirs:
        root = Path(dir_path)
        if not root.is_dir():
            continue
        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            text = _read_text(file_path)
            if text is None:
                continue
            findings.extend(_scan_text(text, str(file_path)))

    for relative_path, absolute_path in config_file_paths.items():
        text = _read_text(Path(absolute_path))
        if text is None:
            continue
        findings.extend(_scan_text(text, relative_path))

    return findings
