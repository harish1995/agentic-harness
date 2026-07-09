"""Read known config file paths as text.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts.
"""

from pathlib import Path

from decompile.unpack import UnpackResult


def extract_config_files(unpack_result: UnpackResult) -> dict[str, str]:
    """Read every path in `unpack_result["config_file_paths"]` as UTF-8 text.
    A decode failure records `"<binary or unreadable>"` for that path instead
    of raising.
    """
    config_files: dict[str, str] = {}
    for relative_path, absolute_path in unpack_result["config_file_paths"].items():
        try:
            config_files[relative_path] = Path(absolute_path).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            config_files[relative_path] = "<binary or unreadable>"
    return config_files
