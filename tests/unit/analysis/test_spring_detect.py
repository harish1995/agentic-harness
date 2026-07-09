from decompile.unpack import UnpackResult

from analysis.spring_detect import detect_spring


def _unpack_result(**overrides) -> UnpackResult:
    base = UnpackResult(
        extract_dir="/tmp/does-not-matter",
        is_spring_boot=False,
        has_spring_security=False,
        spring_evidence=[],
        classes_root="/tmp/does-not-matter",
        nested_jars=[],
        manifest={},
        config_file_paths={},
    )
    base.update(overrides)
    return base


def test_detects_spring_boot_via_boot_inf_dirs(tmp_path):
    (tmp_path / "BOOT-INF" / "classes").mkdir(parents=True)
    (tmp_path / "BOOT-INF" / "lib").mkdir(parents=True)

    result = detect_spring(_unpack_result(extract_dir=str(tmp_path)))

    assert result["is_spring_boot"] is True
    assert any("BOOT-INF/classes" in e for e in result["evidence"])
    assert result["has_spring_security"] is False


def test_detects_spring_boot_via_jar_launcher_class(tmp_path):
    launcher = tmp_path / "org" / "springframework" / "boot" / "loader" / "JarLauncher.class"
    launcher.parent.mkdir(parents=True)
    launcher.write_bytes(b"")

    result = detect_spring(_unpack_result(extract_dir=str(tmp_path)))

    assert result["is_spring_boot"] is True
    assert any("JarLauncher.class" in e for e in result["evidence"])


def test_detects_spring_boot_via_manifest_main_class(tmp_path):
    result = detect_spring(
        _unpack_result(
            extract_dir=str(tmp_path),
            manifest={"Main-Class": "org.springframework.boot.loader.JarLauncher"},
        )
    )

    assert result["is_spring_boot"] is True
    assert any("Main-Class" in e for e in result["evidence"])


def test_detects_spring_boot_via_nested_boot_jar_regex(tmp_path):
    result = detect_spring(
        _unpack_result(
            extract_dir=str(tmp_path),
            nested_jars=["/x/BOOT-INF/lib/spring-boot-2.7.5.jar"],
        )
    )

    assert result["is_spring_boot"] is True
    assert any("spring-boot" in e for e in result["evidence"])


def test_detects_spring_boot_via_application_yml_config(tmp_path):
    result = detect_spring(
        _unpack_result(
            extract_dir=str(tmp_path),
            config_file_paths={"application.yml": "/x/application.yml"},
        )
    )

    assert result["is_spring_boot"] is True
    assert any("application.yml" in e for e in result["evidence"])


def test_has_spring_security_true_when_nested_jar_matches(tmp_path):
    result = detect_spring(
        _unpack_result(
            extract_dir=str(tmp_path),
            nested_jars=[
                "/x/BOOT-INF/lib/spring-boot-2.7.5.jar",
                "/x/BOOT-INF/lib/spring-security-core-5.7.3.jar",
            ],
        )
    )

    assert result["has_spring_security"] is True


def test_not_spring_boot_when_no_signals_present(tmp_path):
    result = detect_spring(_unpack_result(extract_dir=str(tmp_path)))

    assert result["is_spring_boot"] is False
    assert result["has_spring_security"] is False
    assert result["evidence"] == []


def test_has_spring_security_false_when_only_unrelated_nested_jars(tmp_path):
    result = detect_spring(
        _unpack_result(
            extract_dir=str(tmp_path),
            nested_jars=["/x/BOOT-INF/lib/jackson-databind-2.13.4.jar"],
        )
    )

    assert result["has_spring_security"] is False
