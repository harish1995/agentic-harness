from analysis.triage import CATEGORY_KEYWORDS, triage_classes


def test_relevant_file_gets_positive_score_and_category_hint(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "UserController.java").write_text(
        "public class UserController {\n"
        "  public void run(String sql) { PreparedStatement stmt; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = triage_classes(str(app_dir), [])

    assert len(result) == 1
    chunk = result[0]
    assert chunk["class_name"] == "UserController"
    assert chunk["relevance_score"] > 0
    assert "injection" in chunk["category_hints"]
    assert chunk["truncated"] is False


def test_zero_relevance_file_is_excluded(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "PlainPojo.java").write_text(
        "public class PlainPojo {\n  private int value;\n}\n", encoding="utf-8"
    )
    (app_dir / "AuthController.java").write_text(
        "public class AuthController {\n  BCrypt encoder;\n}\n", encoding="utf-8"
    )

    result = triage_classes(str(app_dir), [])

    class_names = {c["class_name"] for c in result}
    assert "PlainPojo" not in class_names
    assert "AuthController" in class_names


def test_truncates_files_over_4000_chars(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    huge_content = "PreparedStatement stmt;\n" + ("x" * 5000)
    (app_dir / "BigDao.java").write_text(huge_content, encoding="utf-8")

    result = triage_classes(str(app_dir), [])

    assert len(result) == 1
    chunk = result[0]
    assert chunk["truncated"] is True
    assert chunk["source_text"].endswith("\n[TRUNCATED]")
    assert len(chunk["source_text"]) == 4000 + len("\n[TRUNCATED]")


def test_scans_both_app_dir_and_lib_dirs(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    lib_dir = tmp_path / "lib1"
    lib_dir.mkdir()
    (app_dir / "AppService.java").write_text("Logger log = null;", encoding="utf-8")
    (lib_dir / "LibDao.java").write_text("PreparedStatement stmt;", encoding="utf-8")

    result = triage_classes(str(app_dir), [str(lib_dir)])

    class_names = {c["class_name"] for c in result}
    assert class_names == {"AppService", "LibDao"}


def test_sort_order_relevance_descending_then_size_ascending(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    # Two category hits (injection + crypto_secrets) -> higher relevance.
    (app_dir / "HighRelevance.java").write_text(
        "PreparedStatement stmt; MessageDigest md;", encoding="utf-8"
    )
    # One category hit -> lower relevance, but larger file.
    (app_dir / "LowRelevance.java").write_text(
        "PreparedStatement stmt;\n" + ("// padding\n" * 50), encoding="utf-8"
    )

    result = triage_classes(str(app_dir), [])

    assert [c["class_name"] for c in result] == ["HighRelevance", "LowRelevance"]


def test_max_classes_cap_triggers_with_more_than_60_relevant_files(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    keywords = ["PreparedStatement", "BCrypt", "MessageDigest", "MultipartFile", "Logger"]
    assert set(keywords) <= {kw for kws in CATEGORY_KEYWORDS.values() for kw in kws}

    for i in range(90):
        keyword = keywords[i % len(keywords)]
        (app_dir / f"Synthetic{i:03d}.java").write_text(
            f"public class Synthetic{i:03d} {{ Object x = {keyword!r}; {keyword} thing;}}\n",
            encoding="utf-8",
        )

    result = triage_classes(str(app_dir), [], max_classes=60, max_total_chars=150_000)

    assert len(result) == 60


def test_max_total_chars_cap_triggers_before_max_classes(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    # Exactly 3000 chars each, all identical relevance -> alphabetical tie-break.
    prefix = "PreparedStatement "
    for i in range(20):
        content = prefix + ("x" * (3000 - len(prefix)))
        assert len(content) == 3000
        (app_dir / f"Class{i:02d}.java").write_text(content, encoding="utf-8")

    result = triage_classes(str(app_dir), [], max_classes=60, max_total_chars=10_000)

    assert len(result) == 3
    assert [c["class_name"] for c in result] == ["Class00", "Class01", "Class02"]


def test_empty_dirs_return_empty_list(tmp_path):
    app_dir = tmp_path / "empty"
    app_dir.mkdir()

    assert triage_classes(str(app_dir), []) == []


def test_nonexistent_dirs_return_empty_list_without_raising(tmp_path):
    assert triage_classes(str(tmp_path / "missing"), [str(tmp_path / "missing-lib")]) == []


def test_non_java_files_are_ignored(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "Notes.txt").write_text("PreparedStatement stmt;", encoding="utf-8")

    assert triage_classes(str(app_dir), []) == []
