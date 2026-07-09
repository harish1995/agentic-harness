from decompile.unpack import UnpackResult

from analysis.config_files import extract_config_files


def _unpack_result(config_file_paths: dict[str, str]) -> UnpackResult:
    return UnpackResult(
        extract_dir="/tmp/does-not-matter",
        is_spring_boot=False,
        has_spring_security=False,
        spring_evidence=[],
        classes_root="/tmp/does-not-matter",
        nested_jars=[],
        manifest={},
        config_file_paths=config_file_paths,
    )


def test_reads_config_files_as_text(tmp_path):
    yml_path = tmp_path / "application.yml"
    yml_path.write_text("server:\n  port: 8080\n", encoding="utf-8")

    result = extract_config_files(_unpack_result({"application.yml": str(yml_path)}))

    assert result == {"application.yml": "server:\n  port: 8080\n"}


def test_multiple_config_files_all_read(tmp_path):
    props_path = tmp_path / "application.properties"
    props_path.write_text("server.port=8080\n", encoding="utf-8")
    dockerfile_path = tmp_path / "Dockerfile"
    dockerfile_path.write_text("FROM eclipse-temurin:17-jre\n", encoding="utf-8")

    result = extract_config_files(
        _unpack_result(
            {
                "application.properties": str(props_path),
                "Dockerfile": str(dockerfile_path),
            }
        )
    )

    assert result["application.properties"] == "server.port=8080\n"
    assert result["Dockerfile"] == "FROM eclipse-temurin:17-jre\n"


def test_binary_file_records_placeholder_instead_of_raising(tmp_path):
    binary_path = tmp_path / "application.yml"
    binary_path.write_bytes(bytes(range(256)))

    result = extract_config_files(_unpack_result({"application.yml": str(binary_path)}))

    assert result["application.yml"] == "<binary or unreadable>"


def test_missing_file_records_placeholder_instead_of_raising(tmp_path):
    missing_path = tmp_path / "does-not-exist.yml"

    result = extract_config_files(_unpack_result({"does-not-exist.yml": str(missing_path)}))

    assert result["does-not-exist.yml"] == "<binary or unreadable>"


def test_empty_config_file_paths_returns_empty_dict():
    result = extract_config_files(_unpack_result({}))

    assert result == {}
