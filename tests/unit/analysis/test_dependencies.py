import zipfile

from decompile.unpack import UnpackResult

from analysis.dependencies import extract_dependencies


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


def test_extracts_dependency_from_manifest():
    result = extract_dependencies(
        _unpack_result(
            manifest={
                "Implementation-Title": "my-app",
                "Implementation-Version": "1.2.3",
            }
        )
    )

    assert {"artifact_id": "my-app", "group_id": None, "version": "1.2.3", "source": "manifest"} in result


def test_no_manifest_dependency_when_title_absent():
    result = extract_dependencies(_unpack_result(manifest={"Implementation-Version": "1.2.3"}))

    assert all(dep["source"] != "manifest" for dep in result)


def test_extracts_dependency_from_nested_jar_filename(tmp_path):
    jar_path = tmp_path / "jackson-databind-2.13.4.jar"
    jar_path.write_bytes(b"")  # unreadable as zip, but filename regex still applies

    result = extract_dependencies(_unpack_result(nested_jars=[str(jar_path)]))

    matches = [d for d in result if d["source"] == "nested_jar_filename"]
    assert matches == [
        {"artifact_id": "jackson-databind", "group_id": None, "version": "2.13.4", "source": "nested_jar_filename"}
    ]


def test_nested_jar_filename_not_matching_pattern_is_skipped(tmp_path):
    jar_path = tmp_path / "no-version-here.jar"
    jar_path.write_bytes(b"")

    result = extract_dependencies(_unpack_result(nested_jars=[str(jar_path)]))

    assert result == []


def _build_pom_properties_jar(path, group_id, artifact_id, version):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"META-INF/maven/{group_id}/{artifact_id}/pom.properties",
            f"groupId={group_id}\nartifactId={artifact_id}\nversion={version}\n",
        )


def test_extracts_dependency_from_pom_properties_inside_nested_jar(tmp_path):
    # Filename deliberately does not match the nested_jar_filename regex (no
    # trailing "-<digit>...") so this exercises the pom.properties source in
    # isolation, distinct from the nested_jar_filename source.
    jar_path = tmp_path / "spring-core-lib.jar"
    _build_pom_properties_jar(jar_path, "org.springframework", "spring-core", "5.3.23")

    result = extract_dependencies(_unpack_result(nested_jars=[str(jar_path)]))

    assert result == [
        {
            "artifact_id": "spring-core",
            "group_id": "org.springframework",
            "version": "5.3.23",
            "source": "pom_properties",
        }
    ]


def test_dedup_by_artifact_id_and_version(tmp_path):
    jar_path = tmp_path / "spring-core-5.3.23.jar"
    _build_pom_properties_jar(jar_path, "org.springframework", "spring-core", "5.3.23")

    manifest = {"Implementation-Title": "spring-core", "Implementation-Version": "5.3.23"}

    result = extract_dependencies(_unpack_result(nested_jars=[str(jar_path)], manifest=manifest))

    matching_pairs = [(d["artifact_id"], d["version"]) for d in result]
    assert matching_pairs.count(("spring-core", "5.3.23")) == 1
    # First occurrence wins (manifest is processed before nested-jar sources).
    kept = next(d for d in result if d["artifact_id"] == "spring-core" and d["version"] == "5.3.23")
    assert kept["source"] == "manifest"


def test_no_dependencies_when_unpack_result_is_empty():
    result = extract_dependencies(_unpack_result())

    assert result == []


def test_pom_properties_missing_artifact_id_is_skipped(tmp_path):
    jar_path = tmp_path / "weird-1.0.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr("META-INF/maven/org.example/weird/pom.properties", "groupId=org.example\nversion=1.0\n")

    result = extract_dependencies(_unpack_result(nested_jars=[str(jar_path)]))

    assert all(d["source"] != "pom_properties" for d in result)
