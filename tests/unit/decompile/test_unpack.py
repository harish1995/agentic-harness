"""Unit tests for src/decompile/unpack.py — real filesystem, synthetic JARs."""

import zipfile
from pathlib import Path

import pytest

from decompile.unpack import unpack_jar

_MANIFEST_PLAIN = (
    "Manifest-Version: 1.0\n"
    "Main-Class: com.example.App\n"
    "Implementation-Title: demo-app\n"
    "Implementation-Version: 1.2.3\n"
)

_MANIFEST_SPRING_BOOT = (
    "Manifest-Version: 1.0\n"
    "Main-Class: org.springframework.boot.loader.JarLauncher\n"
    "Start-Class: com.example.DemoApplication\n"
)


def _write_plain_jar(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", _MANIFEST_PLAIN)
        zf.writestr("com/example/App.class", b"\xca\xfe\xba\xbe-fake-bytecode")
        zf.writestr("com/example/Helper.class", b"\xca\xfe\xba\xbe-fake-bytecode-2")


def _write_spring_boot_jar(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", _MANIFEST_SPRING_BOOT)
        zf.writestr(
            "BOOT-INF/classes/com/example/DemoApplication.class",
            b"\xca\xfe\xba\xbe-fake-bytecode",
        )
        zf.writestr(
            "BOOT-INF/classes/com/example/security/SecurityConfig.class",
            b"\xca\xfe\xba\xbe-fake-bytecode-2",
        )
        zf.writestr("BOOT-INF/classes/application.yml", "server:\n  port: 8080\n")
        zf.writestr("BOOT-INF/lib/spring-boot-3.2.0.jar", b"PK\x03\x04-fake-nested-jar")
        zf.writestr("BOOT-INF/lib/spring-security-core-6.2.0.jar", b"PK\x03\x04-fake-nested-jar-2")
        zf.writestr("BOOT-INF/lib/some-random-lib-1.0.0.jar", b"PK\x03\x04-fake-nested-jar-3")
        zf.writestr("pom.xml", "<project></project>\n")
        zf.writestr("k8s/deployment.yaml", "apiVersion: apps/v1\n")


class TestUnpackPlainJar:
    def test_plain_jar_is_not_spring_boot(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "plain.jar"
        _write_plain_jar(jar_path)
        extract_dir = tmp_path / "extracted-plain"

        result = unpack_jar(str(jar_path), str(extract_dir))

        assert result["is_spring_boot"] is False
        assert result["has_spring_security"] is False
        assert result["spring_evidence"] == []
        assert result["nested_jars"] == []

    def test_plain_jar_classes_root_is_extraction_root(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "plain.jar"
        _write_plain_jar(jar_path)
        extract_dir = tmp_path / "extracted-plain"

        result = unpack_jar(str(jar_path), str(extract_dir))

        assert result["classes_root"] == str(extract_dir.resolve())
        assert (Path(result["classes_root"]) / "com" / "example" / "App.class").is_file()

    def test_plain_jar_manifest_parsed(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "plain.jar"
        _write_plain_jar(jar_path)
        extract_dir = tmp_path / "extracted-plain"

        result = unpack_jar(str(jar_path), str(extract_dir))

        assert result["manifest"]["Main-Class"] == "com.example.App"
        assert result["manifest"]["Implementation-Title"] == "demo-app"
        assert result["manifest"]["Implementation-Version"] == "1.2.3"


class TestUnpackSpringBootJar:
    def test_spring_boot_jar_is_detected(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "app.jar"
        _write_spring_boot_jar(jar_path)
        extract_dir = tmp_path / "extracted-boot"

        result = unpack_jar(str(jar_path), str(extract_dir))

        assert result["is_spring_boot"] is True
        assert len(result["spring_evidence"]) >= 1
        # multiple independent signals should all fire for this fixture
        assert any("BOOT-INF/classes and BOOT-INF/lib" in e for e in result["spring_evidence"])
        assert any("Main-Class" in e for e in result["spring_evidence"])
        assert any("nested Spring Boot jar" in e for e in result["spring_evidence"])
        assert any("config file" in e for e in result["spring_evidence"])

    def test_spring_security_detected_from_nested_jar(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "app.jar"
        _write_spring_boot_jar(jar_path)
        extract_dir = tmp_path / "extracted-boot"

        result = unpack_jar(str(jar_path), str(extract_dir))

        assert result["has_spring_security"] is True

    def test_spring_boot_classes_root_is_boot_inf_classes(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "app.jar"
        _write_spring_boot_jar(jar_path)
        extract_dir = tmp_path / "extracted-boot"

        result = unpack_jar(str(jar_path), str(extract_dir))

        expected = str((extract_dir / "BOOT-INF" / "classes").resolve())
        assert result["classes_root"] == expected

    def test_nested_jars_located_but_not_extracted(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "app.jar"
        _write_spring_boot_jar(jar_path)
        extract_dir = tmp_path / "extracted-boot"

        result = unpack_jar(str(jar_path), str(extract_dir))

        nested_names = sorted(Path(p).name for p in result["nested_jars"])
        assert nested_names == [
            "some-random-lib-1.0.0.jar",
            "spring-boot-3.2.0.jar",
            "spring-security-core-6.2.0.jar",
        ]
        for nested in result["nested_jars"]:
            assert Path(nested).is_file()
            # nested jars are located, not unzipped further
            sibling_extract = Path(nested).with_suffix("")
            assert not sibling_extract.is_dir()

    def test_config_file_paths_discovered(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "app.jar"
        _write_spring_boot_jar(jar_path)
        extract_dir = tmp_path / "extracted-boot"

        result = unpack_jar(str(jar_path), str(extract_dir))

        assert "BOOT-INF/classes/application.yml" in result["config_file_paths"]
        assert "pom.xml" in result["config_file_paths"]
        assert "k8s/deployment.yaml" in result["config_file_paths"]
        for relative_path, absolute_path in result["config_file_paths"].items():
            assert Path(absolute_path).is_file(), relative_path

    def test_config_file_paths_exclude_nested_jar_contents(self, tmp_path: Path) -> None:
        jar_path = tmp_path / "app.jar"
        _write_spring_boot_jar(jar_path)
        extract_dir = tmp_path / "extracted-boot"

        result = unpack_jar(str(jar_path), str(extract_dir))

        for relative_path in result["config_file_paths"]:
            assert "BOOT-INF/lib" not in relative_path


class TestUnpackFailurePaths:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist.jar"
        with pytest.raises(Exception):
            unpack_jar(str(missing), str(tmp_path / "out"))

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.jar"
        empty.write_bytes(b"")
        with pytest.raises(Exception):
            unpack_jar(str(empty), str(tmp_path / "out"))

    def test_non_zip_file_raises(self, tmp_path: Path) -> None:
        bogus = tmp_path / "notreally.jar"
        bogus.write_text("this is definitely not a zip/jar file\n")
        with pytest.raises(Exception):
            unpack_jar(str(bogus), str(tmp_path / "out"))
