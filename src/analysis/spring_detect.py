"""Heuristic Spring Boot / Spring Security detection over an already-unpacked JAR.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts. This is the
"real", reusable implementation of the 5-signal heuristic; `decompile/unpack.py`
duplicates the same rules inline (by design, to avoid a build-order dependency)
and both must agree bit-for-bit — do not diverge from the rules below.
"""

import re
from pathlib import Path
from typing import TypedDict

from decompile.unpack import UnpackResult

_BOOT_LAUNCHER_CLASS = "org/springframework/boot/loader/JarLauncher.class"
_BOOT_MAIN_CLASSES = (
    "org.springframework.boot.loader.JarLauncher",
    "org.springframework.boot.loader.WarLauncher",
)
_SPRING_BOOT_JAR_RE = re.compile(r"^spring-boot(-\w+)*-\d")
_SPRING_SECURITY_JAR_RE = re.compile(r"^spring-security-\w+-\d")
_SPRING_BOOT_CONFIG_NAMES = {"application.yml", "application.yaml", "application.properties"}


class SpringDetection(TypedDict):
    is_spring_boot: bool
    has_spring_security: bool
    evidence: list[str]


def detect_spring(unpack_result: UnpackResult) -> SpringDetection:
    """Apply the fixed 5-signal Spring Boot heuristic (ALL evaluated;
    is_spring_boot = True if ANY match) plus the Spring Security nested-jar
    signal, over an `UnpackResult`.
    """
    evidence: list[str] = []
    extract_root = Path(unpack_result["extract_dir"])
    manifest = unpack_result["manifest"]
    nested_jars = unpack_result["nested_jars"]
    config_file_paths = unpack_result["config_file_paths"]

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

    return SpringDetection(
        is_spring_boot=bool(evidence),
        has_spring_security=has_spring_security,
        evidence=evidence,
    )
