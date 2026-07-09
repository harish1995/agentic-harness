"""Dependency extraction over an already-unpacked JAR.

Pinned contract — see `spec/agent.md` -> Internal Module Contracts.
"""

import re
import zipfile
from pathlib import Path
from typing import TypedDict

from decompile.unpack import UnpackResult

_NESTED_JAR_FILENAME_RE = re.compile(r"^(?P<artifact>[A-Za-z0-9._-]+?)-(?P<version>\d[\w.\-]*)\.jar$")
_POM_PROPERTIES_RE = re.compile(r"^META-INF/maven/[^/]+/[^/]+/pom\.properties$")


class DependencyInfo(TypedDict):
    artifact_id: str
    group_id: str | None
    version: str | None
    source: str


def _from_manifest(unpack_result: UnpackResult) -> DependencyInfo | None:
    manifest = unpack_result["manifest"]
    title = manifest.get("Implementation-Title")
    version = manifest.get("Implementation-Version")
    if not title:
        return None
    return DependencyInfo(artifact_id=title, group_id=None, version=version, source="manifest")


def _from_nested_jar_filenames(unpack_result: UnpackResult) -> list[DependencyInfo]:
    deps: list[DependencyInfo] = []
    for jar_path in unpack_result["nested_jars"]:
        name = Path(jar_path).name
        match = _NESTED_JAR_FILENAME_RE.match(name)
        if not match:
            continue
        deps.append(
            DependencyInfo(
                artifact_id=match.group("artifact"),
                group_id=None,
                version=match.group("version"),
                source="nested_jar_filename",
            )
        )
    return deps


def _parse_properties(text: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("!"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        props[key.strip()] = value.strip()
    return props


def _from_pom_properties(unpack_result: UnpackResult) -> list[DependencyInfo]:
    deps: list[DependencyInfo] = []
    for jar_path in unpack_result["nested_jars"]:
        try:
            with zipfile.ZipFile(jar_path) as archive:
                for name in archive.namelist():
                    if not _POM_PROPERTIES_RE.match(name):
                        continue
                    try:
                        text = archive.read(name).decode("utf-8", errors="replace")
                    except (KeyError, OSError):
                        continue
                    props = _parse_properties(text)
                    artifact_id = props.get("artifactId")
                    if not artifact_id:
                        continue
                    deps.append(
                        DependencyInfo(
                            artifact_id=artifact_id,
                            group_id=props.get("groupId"),
                            version=props.get("version"),
                            source="pom_properties",
                        )
                    )
        except (zipfile.BadZipFile, OSError):
            continue
    return deps


def extract_dependencies(unpack_result: UnpackResult) -> list[DependencyInfo]:
    """Extract dependency name/version info from three sources — manifest,
    nested jar filenames, and nested pom.properties — deduplicated by
    (artifact_id, version).
    """
    candidates: list[DependencyInfo] = []

    manifest_dep = _from_manifest(unpack_result)
    if manifest_dep is not None:
        candidates.append(manifest_dep)

    candidates.extend(_from_nested_jar_filenames(unpack_result))
    candidates.extend(_from_pom_properties(unpack_result))

    deduped: dict[tuple[str, str | None], DependencyInfo] = {}
    for dep in candidates:
        key = (dep["artifact_id"], dep["version"])
        if key not in deduped:
            deduped[key] = dep

    return list(deduped.values())
