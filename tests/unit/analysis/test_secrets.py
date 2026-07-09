from analysis.secrets import scan_secrets

# Synthetic, non-functional fixture values only -- never real credentials.
# Well-known-shaped patterns (AWS/Slack/Stripe/GitHub) are assembled via
# runtime string concatenation rather than written as a single contiguous
# literal, so this file's source text never contains a string that looks
# like a real secret to automated secret scanners (e.g. GitHub push
# protection) -- the concatenated *value* still matches the regex under
# test at runtime, which is all these tests need.
_AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
_SLACK_TOKEN = "xoxb-" + "1234567890123-abcdEFGHij"
_STRIPE_KEY = "sk_" + "live_51H8anExampleLongKeyAbCdEfGh1234"
_GITHUB_TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"

# One fixture line per pattern, each independently matchable.
_FIXTURES: dict[str, str] = {
    "AWS Access Key ID": f'String key = "{_AWS_ACCESS_KEY_ID}";',
    "AWS Secret Access Key": f'aws_secret_key = "{_AWS_SECRET_KEY}"',
    "Generic API Key": 'apiKey = "ABCDEFGHIJKLMNOPQRSTUVWX"',
    "Private Key Block": "-----BEGIN RSA PRIVATE KEY-----",
    "JDBC Creds in URL": "jdbc:mysql://user:s3cretPass@localhost:3306/mydb",
    "Generic DB Creds in URL": "postgres://admin:hunter2@db.example.com:5432/prod",
    "JWT / Generic Secret Key": 'jwt_secret = "supersecretvalue123"',
    "Hardcoded Password": 'password = "hunter2pass"',
    "Slack Token": _SLACK_TOKEN,
    "Stripe Live Key": _STRIPE_KEY,
    "GitHub Token": _GITHUB_TOKEN,
}


def _secret_value(pattern_name: str, line: str) -> str:
    """The raw value each fixture line is designed to leak, used to assert
    the redacted form never contains its full middle portion."""
    values = {
        "AWS Access Key ID": _AWS_ACCESS_KEY_ID,
        "AWS Secret Access Key": _AWS_SECRET_KEY,
        "Generic API Key": "ABCDEFGHIJKLMNOPQRSTUVWX",
        "JDBC Creds in URL": "s3cretPass",
        "Generic DB Creds in URL": "hunter2",
        "JWT / Generic Secret Key": "supersecretvalue123",
        "Hardcoded Password": "hunter2pass",
        "Slack Token": _SLACK_TOKEN.split("-", 1)[1],
        "Stripe Live Key": _STRIPE_KEY.split("_", 1)[1],
        "GitHub Token": _GITHUB_TOKEN.split("_", 1)[1],
    }
    return values.get(pattern_name, line)


def test_each_pattern_in_table_is_detected(tmp_path):
    for pattern_name, line in _FIXTURES.items():
        file_path = tmp_path / f"{pattern_name.replace(' ', '_').replace('/', '_')}.java"
        file_path.write_text(f"// noise line\n{line}\n// trailing\n", encoding="utf-8")

        findings = scan_secrets([str(tmp_path)], {})

        matches = [f for f in findings if f["pattern_name"] == pattern_name and f["file_path"] == str(file_path)]
        assert matches, f"pattern {pattern_name!r} did not match its fixture line"
        finding = matches[0]
        assert finding["line_number"] == 2
        assert finding["confidence"] in {"High", "Medium", "Low"}

        file_path.unlink()


def test_redacted_secret_never_contains_full_raw_secret_middle(tmp_path):
    for pattern_name, line in _FIXTURES.items():
        file_path = tmp_path / "secret.java"
        file_path.write_text(line, encoding="utf-8")

        findings = scan_secrets([str(tmp_path)], {})
        matches = [f for f in findings if f["pattern_name"] == pattern_name]
        assert matches, f"pattern {pattern_name!r} did not match"

        secret_value = _secret_value(pattern_name, line)
        redacted = matches[0]["matched_text_redacted"]
        assert secret_value not in redacted
        assert "…" in redacted
        assert line not in redacted

        file_path.unlink()


def test_confidence_levels_match_table():
    expected = {
        "AWS Access Key ID": "High",
        "AWS Secret Access Key": "High",
        "Generic API Key": "Medium",
        "Private Key Block": "High",
        "JDBC Creds in URL": "High",
        "Generic DB Creds in URL": "High",
        "JWT / Generic Secret Key": "Medium",
        "Hardcoded Password": "Low",
        "Slack Token": "High",
        "Stripe Live Key": "High",
        "GitHub Token": "High",
    }
    from analysis.secrets import _PATTERNS

    actual = {p.name: p.confidence for p in _PATTERNS}
    assert actual == expected


def test_empty_input_returns_empty_list():
    assert scan_secrets([], {}) == []


def test_nonexistent_dir_is_skipped_without_raising(tmp_path):
    missing_dir = str(tmp_path / "does-not-exist")

    assert scan_secrets([missing_dir], {}) == []


def test_no_matches_in_clean_file_returns_empty(tmp_path):
    clean_file = tmp_path / "Clean.java"
    clean_file.write_text("public class Clean { void hello() { System.out.println(\"hi\"); } }", encoding="utf-8")

    assert scan_secrets([str(tmp_path)], {}) == []


def test_binary_or_unreadable_file_is_skipped(tmp_path):
    binary_file = tmp_path / "binary.class"
    binary_file.write_bytes(bytes(range(256)))

    # Must not raise, regardless of whether it happens to "match" garbage bytes.
    scan_secrets([str(tmp_path)], {})


def test_short_secret_in_keyword_wrapped_patterns_is_not_leaked(tmp_path):
    """Regression test for the redaction-scope bug: `_redact` was called on
    `match.group(0)` (keyword + syntax + secret) instead of on the real
    secret value for the four keyword-wrapped patterns. Two distinct
    failures resulted:

    1. For short real secrets (<= 8 chars), the whole match (keyword +
       syntax + secret) was always > 8 chars, so the "reveal only 2 chars"
       safety branch never fired. Instead the "first 4 / last 4 of match"
       branch fired, and because the match ends right at the closing quote,
       its last 4 characters landed on the last 3-4 characters of the real
       secret — e.g. `password = "Xk7Q"` redacted to `'pass…k7Q"'`, leaking
       3 of the 4 real secret characters.
    2. For longer real secrets, the revealed "first 4" chars were the
       keyword text (e.g. `apiK`) rather than the real secret's first 4
       chars, and the revealed "last 4" chars were 3 real secret chars plus
       the trailing quote character rather than the true last 4 real chars
       — neither matches the intended first4/…/last4-of-secret contract.

    This test asserts the redacted output's revealed prefix/suffix are
    exactly (and only) the real secret's own characters, at the exact
    lengths the redaction contract promises, for all four affected
    patterns.
    """
    cases: dict[str, tuple[str, str]] = {
        # pattern_name: (source_line, real_secret_value)
        "Hardcoded Password": ('password = "Xk7Q"', "Xk7Q"),
        "Generic API Key": ('apiKey = "ABCDEFGHIJKLMNOP"', "ABCDEFGHIJKLMNOP"),
        "JWT / Generic Secret Key": ('jwt_secret = "Sup3rSec"', "Sup3rSec"),
        "AWS Secret Access Key": (
            'aws_access_key = "' + "Bz9" + "Q" * 37 + '"',
            "Bz9" + "Q" * 37,
        ),
    }

    for pattern_name, (line, secret_value) in cases.items():
        file_path = tmp_path / "secret.java"
        file_path.write_text(line, encoding="utf-8")

        findings = scan_secrets([str(tmp_path)], {})
        matches = [f for f in findings if f["pattern_name"] == pattern_name]
        assert matches, f"pattern {pattern_name!r} did not match its fixture line"

        redacted = matches[0]["matched_text_redacted"]
        assert "…" in redacted

        if len(secret_value) <= 8:
            # The exact failure mode the QA report reproduced: for short
            # secrets, the last few real secret characters must never
            # appear immediately before a closing quote/boundary character
            # in the redacted output.
            assert not redacted.rstrip("\"'").endswith(secret_value[-3:]), (
                f"{pattern_name!r}: redacted text {redacted!r} ends with the "
                f"real secret's tail {secret_value[-3:]!r} right before a "
                "boundary character"
            )

            # Short-secret safety branch must fire: only the real secret's
            # own first 2 chars (never keyword/syntax text, never the tail)
            # may be revealed.
            expected = "…" if len(secret_value) <= 2 else f"{secret_value[:2]}…"
            assert redacted == expected, (
                f"{pattern_name!r}: short secret {secret_value!r} redacted as "
                f"{redacted!r}, expected {expected!r}"
            )
        else:
            # Long-secret branch: revealed prefix/suffix must be exactly the
            # real secret's own first 4 / last 4 characters — not keyword
            # text and not a quote-contaminated tail.
            expected = f"{secret_value[:4]}…{secret_value[-4:]}"
            assert redacted == expected, (
                f"{pattern_name!r}: secret {secret_value!r} redacted as "
                f"{redacted!r}, expected {expected!r}"
            )

        file_path.unlink()


def test_scans_config_files_by_relative_path(tmp_path):
    config_path = tmp_path / "application.properties"
    config_path.write_text('password: "hunter2pass"', encoding="utf-8")

    findings = scan_secrets([], {"application.properties": str(config_path)})

    matches = [f for f in findings if f["pattern_name"] == "Hardcoded Password"]
    assert matches
    assert matches[0]["file_path"] == "application.properties"
