"""Shell out to the vendored CFR decompiler.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts. Other
Phase-1 slices depend on these exact function/field names; do not rename.
"""

import subprocess
from pathlib import Path
from typing import TypedDict


class DecompileResult(TypedDict):
    output_dir: str
    class_count: int
    errors: list[str]


def _count_java_files(output_dir: Path) -> int:
    return sum(1 for _ in output_dir.rglob("*.java"))


def _resolve_cfr_targets(classes_root_or_jar: str) -> tuple[list[str], list[str]]:
    """Resolve the positional CFR CLI arguments for `classes_root_or_jar`.

    CFR's CLI cannot decompile a bare directory path directly (it resolves it
    as a single "class" and fails with a CannotLoadClassException) — a
    directory of `.class` files must be passed as individual `.class` file
    arguments. A jar file is passed through as-is; CFR handles jars natively.
    Returns `(targets, errors)` — `errors` is non-empty when nothing could be
    resolved (missing path, or an empty classes directory).
    """
    path = Path(classes_root_or_jar)
    if path.is_dir():
        class_files = sorted(str(p) for p in path.rglob("*.class"))
        if not class_files:
            return [], [f"No .class files found under classes_root_or_jar: {classes_root_or_jar}"]
        return class_files, []
    if path.is_file():
        return [str(path)], []
    return [], [f"classes_root_or_jar does not exist: {classes_root_or_jar}"]


def decompile_classes(
    classes_root_or_jar: str,
    output_dir: str,
    *,
    cfr_jar_path: str,
    java_bin: str = "java",
    timeout_s: int = 120,
) -> DecompileResult:
    """Decompile `classes_root_or_jar` into `.java` source under `output_dir`
    using the vendored CFR decompiler.

    Never raises for a CFR failure (non-zero exit, timeout, or missing input) —
    those are recorded in `errors` with `class_count=0` so the caller decides
    fatality. Only a truly unexpected local error (e.g. `output_dir` cannot be
    created) may raise, and even that is caught here where reasonably possible.
    """
    output_path = Path(output_dir)
    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return DecompileResult(output_dir=output_dir, class_count=0, errors=[f"Could not create output_dir: {exc}"])

    targets, resolve_errors = _resolve_cfr_targets(classes_root_or_jar)
    if resolve_errors:
        return DecompileResult(output_dir=output_dir, class_count=0, errors=resolve_errors)

    command = [java_bin, "-jar", cfr_jar_path, *targets, "--outputdir", output_dir]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return DecompileResult(
            output_dir=output_dir,
            class_count=0,
            errors=[f"CFR timed out after {timeout_s}s"],
        )
    except OSError as exc:
        return DecompileResult(
            output_dir=output_dir,
            class_count=0,
            errors=[f"Failed to invoke CFR ({java_bin}): {exc}"],
        )

    if completed.returncode != 0:
        stderr_tail = completed.stderr.strip()[-2000:]
        return DecompileResult(
            output_dir=output_dir,
            class_count=0,
            errors=[f"CFR exited with code {completed.returncode}: {stderr_tail}"],
        )

    class_count = _count_java_files(output_path)
    return DecompileResult(output_dir=output_dir, class_count=class_count, errors=[])
