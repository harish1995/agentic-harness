"""Score and select a bounded, security-relevant subset of decompiled classes.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts and the
"Triage Heuristic (concrete)" subsection. This is the project's cost-control
mechanism: get the stopping-condition logic exactly right.
"""

from pathlib import Path
from typing import TypedDict

_TRUNCATE_CHARS = 4000
_TRUNCATE_MARKER = "\n[TRUNCATED]"

_PATH_FILENAME_KEYWORDS = [
    "Controller", "Security", "Auth", "Filter", "Config", "Crypto", "Encrypt",
    "Password", "Token", "Jwt", "Session", "Repository", "Dao", "Service",
    "Upload", "Serial", "Deserial", "Xml", "Ldap",
]

_PACKAGE_PATH_KEYWORDS = ["security", "auth", "config", "crypto", "filter", "web", "controller", "rest"]

CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "injection": [
        "PreparedStatement", "Statement.execute", "createStatement", "@Query",
        "EntityManager", "Runtime.exec", "ProcessBuilder", "DocumentBuilder",
        "SAXParser", "XPath",
    ],
    "authn_authz": [
        "@PreAuthorize", "@Secured", "HttpSecurity", "WebSecurityConfigurerAdapter",
        "SecurityFilterChain", "PasswordEncoder", "BCrypt", "Jwts.", "jwt",
        "UserDetailsService",
    ],
    "crypto_secrets": [
        "MessageDigest", "Cipher.getInstance", "KeyGenerator", "SecureRandom",
        "new Random", "@Value(", "System.getenv",
    ],
    "deserialization_upload": [
        "ObjectInputStream", "readObject", "XMLDecoder", "MultipartFile",
        "FileOutputStream", "Files.write",
    ],
    "config_logging": ["Logger", "@ConfigurationProperties", ".properties", ".yml"],
}

_JAVA_LIKE_SUFFIXES = {".java"}


class TriagedChunk(TypedDict):
    file_path: str
    class_name: str
    source_text: str
    relevance_score: int
    category_hints: list[str]
    truncated: bool


class _Candidate(TypedDict):
    path: Path
    relevance_score: int
    category_hints: list[str]
    file_size: int


def _score_file(path: Path, text: str) -> tuple[int, list[str]]:
    score = 0
    full_path_lower = path.as_posix().lower()
    package_path_lower = path.parent.as_posix().lower()

    for keyword in _PATH_FILENAME_KEYWORDS:
        if keyword.lower() in full_path_lower:
            score += 1

    for keyword in _PACKAGE_PATH_KEYWORDS:
        if keyword in package_path_lower:
            score += 1

    category_hints: list[str] = []
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            category_hints.append(category)
            score += 1

    return score, category_hints


def _iter_java_files(root_dir: str) -> list[Path]:
    root = Path(root_dir)
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in _JAVA_LIKE_SUFFIXES)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def triage_classes(
    decompiled_app_dir: str,
    decompiled_lib_dirs: list[str],
    *,
    max_classes: int = 60,
    max_total_chars: int = 150_000,
    per_category_max_chars: int = 30_000,
) -> list[TriagedChunk]:
    """Score every decompiled `.java`-like file, exclude zero-relevance files,
    sort by relevance descending then file size ascending, and take files
    until either `max_classes` is reached or the next file's (possibly
    truncated) length would push the running character total past
    `max_total_chars` — whichever bound is hit first.
    """
    all_files: list[Path] = []
    all_files.extend(_iter_java_files(decompiled_app_dir))
    for lib_dir in decompiled_lib_dirs:
        all_files.extend(_iter_java_files(lib_dir))

    scored: list[tuple[Path, str, int, list[str]]] = []
    for path in all_files:
        text = _read_text(path)
        if text is None:
            continue
        relevance_score, category_hints = _score_file(path, text)
        if relevance_score == 0:
            continue
        scored.append((path, text, relevance_score, category_hints))

    scored.sort(key=lambda item: (-item[2], item[0].stat().st_size))

    chunks: list[TriagedChunk] = []
    running_total = 0
    for path, text, relevance_score, category_hints in scored:
        if len(chunks) >= max_classes:
            break

        truncated = len(text) > _TRUNCATE_CHARS
        source_text = text[:_TRUNCATE_CHARS] + _TRUNCATE_MARKER if truncated else text

        if running_total + len(source_text) > max_total_chars:
            break

        running_total += len(source_text)
        chunks.append(
            TriagedChunk(
                file_path=str(path),
                class_name=path.stem,
                source_text=source_text,
                relevance_score=relevance_score,
                category_hints=category_hints,
                truncated=truncated,
            )
        )

    return chunks
