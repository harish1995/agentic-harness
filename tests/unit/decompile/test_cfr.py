"""Unit tests for src/decompile/cfr.py — real javac compile + real CFR jar."""

import shutil
import subprocess
from pathlib import Path

import pytest

from decompile.cfr import decompile_classes

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CFR_JAR_PATH = _REPO_ROOT / "tools" / "cfr-0.152.jar"

_JAVA_SOURCE = """
package com.example.demo;

public class Greeter {
    public String greet(String name) {
        return "Hello, " + name + "!";
    }
}
"""

pytestmark = pytest.mark.skipif(
    not _CFR_JAR_PATH.is_file(), reason=f"CFR jar not vendored at {_CFR_JAR_PATH}"
)


@pytest.fixture(scope="module")
def compiled_classes_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Compile a real tiny .java file to a .class with javac."""
    src_dir = tmp_path_factory.mktemp("java-src")
    package_dir = src_dir / "com" / "example" / "demo"
    package_dir.mkdir(parents=True)
    source_file = package_dir / "Greeter.java"
    source_file.write_text(_JAVA_SOURCE, encoding="utf-8")

    classes_dir = tmp_path_factory.mktemp("java-classes")
    result = subprocess.run(
        ["javac", "-d", str(classes_dir), str(source_file)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"javac failed: {result.stderr}"
    assert (classes_dir / "com" / "example" / "demo" / "Greeter.class").is_file()
    return classes_dir


class TestDecompileClassesSuccess:
    def test_decompiles_real_class_via_real_cfr(self, compiled_classes_dir: Path, tmp_path: Path) -> None:
        output_dir = tmp_path / "decompiled"

        result = decompile_classes(
            str(compiled_classes_dir),
            str(output_dir),
            cfr_jar_path=str(_CFR_JAR_PATH),
        )

        assert result["errors"] == []
        assert result["class_count"] >= 1
        assert result["output_dir"] == str(output_dir)

    def test_decompiled_source_contains_class_name(self, compiled_classes_dir: Path, tmp_path: Path) -> None:
        output_dir = tmp_path / "decompiled"

        result = decompile_classes(
            str(compiled_classes_dir),
            str(output_dir),
            cfr_jar_path=str(_CFR_JAR_PATH),
        )

        java_files = list(Path(result["output_dir"]).rglob("*.java"))
        assert java_files, "expected at least one decompiled .java file"
        combined_source = "\n".join(f.read_text(encoding="utf-8") for f in java_files)
        assert "Greeter" in combined_source
        assert "greet" in combined_source


class TestDecompileClassesFailurePaths:
    def test_bogus_input_path_returns_errors_without_raising(self, tmp_path: Path) -> None:
        bogus_input = tmp_path / "does-not-exist-classes"
        output_dir = tmp_path / "decompiled-bogus"

        result = decompile_classes(
            str(bogus_input),
            str(output_dir),
            cfr_jar_path=str(_CFR_JAR_PATH),
        )

        assert result["errors"] != []
        assert result["class_count"] == 0
        assert result["output_dir"] == str(output_dir)

    def test_missing_java_binary_returns_errors_without_raising(
        self, compiled_classes_dir: Path, tmp_path: Path
    ) -> None:
        output_dir = tmp_path / "decompiled-missing-java"

        result = decompile_classes(
            str(compiled_classes_dir),
            str(output_dir),
            cfr_jar_path=str(_CFR_JAR_PATH),
            java_bin="definitely-not-a-real-java-binary",
        )

        assert result["errors"] != []
        assert result["class_count"] == 0

    def test_timeout_returns_errors_without_raising(self, compiled_classes_dir: Path, tmp_path: Path) -> None:
        output_dir = tmp_path / "decompiled-timeout"

        result = decompile_classes(
            str(compiled_classes_dir),
            str(output_dir),
            cfr_jar_path=str(_CFR_JAR_PATH),
            timeout_s=0,
        )

        assert result["errors"] != []
        assert "timed out" in result["errors"][0].lower()
        assert result["class_count"] == 0


def test_java_and_javac_available_on_path() -> None:
    """Sanity check that this environment actually has the JDK prerequisite documented
    in spec/roadmap.md — a skipped-everything-else run would otherwise look green
    for the wrong reason."""
    assert shutil.which("java") is not None
    assert shutil.which("javac") is not None
