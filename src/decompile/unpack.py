"""Unpack a JAR file and detect Spring Boot fat-JAR structure.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts. Other
Phase-1 slices depend on these exact function/field names; do not rename.
"""

import re
import zipfile
from pathlib import Path
from typing import TypedDict

_BOOT_LAUNCHER_CLASS = "org/springframework/boot/loader/JarLauncher.class"
_BOOT_MAIN_CLASSES = (
    "org.springframework.boot.loader.JarLauncher",
    "org.springframework.boot.loader.WarLauncher",
)
_SPRING_BOOT_JAR_RE = re.compile(r"^spring-boot(-\w+)*-\d")
_SPRING_SECURITY_JAR_RE = re.compile(r"^spring-security-\w+-\d")
_SPRING_BOOT_CONFIG_NAMES = {"application.yml", "application.yaml", "application.properties"}

_CONFIG_EXACT_NAMES = {
    "application.yml",
    "application.yaml",
    "application.properties",
    "logback.xml",
    "logback-spring.xml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Dockerfile",
}
_CONFIG_PATTERN_RES = (
    re.compile(r"^application-.+\.ya?ml$"),
    re.compile(r"^application-.+\.properties$"),
)
_K8S_DIR_NAMES = {"k8s", "kubernetes"}
_YAML_SUFFIXES = {".yaml", ".yml"}


class UnpackResult(TypedDict):
    extract_dir: str
    is_spring_boot: bool
    has_spring_security: bool
    spring_evidence: list[str]
    classes_root: str  # dir of raw .class files for the "app" component
    nested_jars: list[str]  # absolute paths to BOOT-INF/lib/*.jar; [] for plain jars
    manifest: dict[str, str]
    config_file_paths: dict[str, str]  # relative path -> absolute path


def _parse_manifest(manifest_path: Path) -> dict[str, str]:
    """Parse a MANIFEST.MF file into a flat dict, handling line continuations."""
    manifest: dict[str, str] = {}
    raw = manifest_path.read_text(encoding="utf-8", errors="replace")
    # MANIFEST.MF continuation lines start with a single leading space.
    lines: list[str] = []
    for line in raw.splitlines():
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    for line in lines:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        manifest[key.strip()] = value.strip()
    return manifest


def _is_config_file(relative_path: Path) -> bool:
    name = relative_path.name
    if name in _CONFIG_EXACT_NAMES:
        return True
    if any(rx.match(name) for rx in _CONFIG_PATTERN_RES):
        return True
    if relative_path.suffix in _YAML_SUFFIXES:
        parts = {p.lower() for p in relative_path.parts[:-1]}
        if parts & _K8S_DIR_NAMES:
            return True
    return False


def _is_under_nested_lib_jar(relative_path: Path) -> bool:
    """True if this path is *inside* a nested BOOT-INF/lib/*.jar (never happens for
    top-level extraction, since we never unzip nested jars) — kept as an explicit
    guard for clarity/future-proofing rather than relying on absence alone."""
    parts = relative_path.parts
    return "BOOT-INF" in parts and "lib" in parts and relative_path.suffix == ".jar"


def _find_config_file_paths(extract_root: Path) -> dict[str, str]:
    config_file_paths: dict[str, str] = {}
    for path in extract_root.rglob("*"):
        if not path.is_file():
            continue
        relative_path = path.relative_to(extract_root)
        if _is_under_nested_lib_jar(relative_path):
            continue
        if _is_config_file(relative_path):
            config_file_paths[relative_path.as_posix()] = str(path.resolve())
    return config_file_paths


def _find_nested_jars(extract_root: Path) -> list[str]:
    lib_dir = extract_root / "BOOT-INF" / "lib"
    if not lib_dir.is_dir():
        return []
    return sorted(str(p.resolve()) for p in lib_dir.glob("*.jar"))


def _detect_spring(
    extract_root: Path,
    manifest: dict[str, str],
    nested_jars: list[str],
    config_file_paths: dict[str, str],
) -> tuple[bool, bool, list[str]]:
    evidence: list[str] = []

    boot_classes = extract_root / "BOOT-INF" / "classes"
    boot_lib = extract_root / "BOOT-INF" / "lib"
    if boot_classes.is_dir() and boot_lib.is_dir():
        evidence.append("BOOT-INF/classes and BOOT-INF/lib both present")

    if (extract_root / _BOOT_LAUNCHER_CLASS).is_file():
        evidence.append("org/springframework/boot/loader/JarLauncher.class present")

    main_class = manifest.get("Main-Class")
    if main_class in _BOOT_MAIN_CLASSES:
        evidence.append(f"MANIFEST Main-Class={main_class}")

    matched_boot_jars = [
        Path(jar).name for jar in nested_jars if _SPRING_BOOT_JAR_RE.match(Path(jar).name)
    ]
    if matched_boot_jars:
        evidence.append(f"nested Spring Boot jar(s): {', '.join(matched_boot_jars)}")

    matched_config_names = {Path(rel).name for rel in config_file_paths} & _SPRING_BOOT_CONFIG_NAMES
    if matched_config_names:
        evidence.append(f"Spring Boot config file(s) present: {', '.join(sorted(matched_config_names))}")

    has_spring_security = any(
        _SPRING_SECURITY_JAR_RE.match(Path(jar).name) for jar in nested_jars
    )

    return bool(evidence), has_spring_security, evidence


def unpack_jar(jar_path: str, extract_dir: str) -> UnpackResult:
    """Unzip `jar_path` into `extract_dir`, detect Spring Boot structure, locate
    nested lib jars (without unzipping them), parse the manifest, and locate
    config files.

    Raises a plain Python exception with an actionable message if `jar_path`
    is not a valid JAR/ZIP or is empty/unreadable.
    """
    source = Path(jar_path)
    if not source.is_file():
        raise ValueError(f"JAR file does not exist or is not a regular file: {jar_path}")
    if source.stat().st_size == 0:
        raise ValueError(f"JAR file is empty: {jar_path}")
    if not zipfile.is_zipfile(source):
        raise ValueError(f"File is not a valid JAR/ZIP archive: {jar_path}")

    extract_root = Path(extract_dir)
    extract_root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(source) as archive:
        archive.extractall(extract_root)

    manifest_path = extract_root / "META-INF" / "MANIFEST.MF"
    manifest = _parse_manifest(manifest_path) if manifest_path.is_file() else {}

    nested_jars = _find_nested_jars(extract_root)
    config_file_paths = _find_config_file_paths(extract_root)

    is_spring_boot, has_spring_security, spring_evidence = _detect_spring(
        extract_root, manifest, nested_jars, config_file_paths
    )

    boot_classes_dir = extract_root / "BOOT-INF" / "classes"
    classes_root = str(boot_classes_dir.resolve()) if boot_classes_dir.is_dir() else str(extract_root.resolve())

    return UnpackResult(
        extract_dir=str(extract_root.resolve()),
        is_spring_boot=is_spring_boot,
        has_spring_security=has_spring_security,
        spring_evidence=spring_evidence,
        classes_root=classes_root,
        nested_jars=nested_jars,
        manifest=manifest,
        config_file_paths=config_file_paths,
    )
