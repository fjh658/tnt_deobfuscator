"""Minimal self-contained PEP 517 backend for offline installs.

This backend intentionally avoids external build dependencies so that
`pip install -e .` and URL-based installs can work in restricted environments.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except Exception:
        tomllib = None

DEFAULT_PROJECT = {
    "name": "tnt-deobfuscator",
    "version": "0.1.0",
    "description": "Static and dynamic deobfuscator for TNT-style Mach-O x86_64/arm64 binaries",
    "license": "MIT",
    "requires_python": ">=3.10",
    "dependencies": ["unicorn>=2.0.1"],
    "scripts": {
        "tnt-deobfuscator": "tnt_deobfuscator.cli:main",
        "tnt_deobfuscator": "tnt_deobfuscator.cli:main",
    },
}

PROJECT_ROOT = Path(__file__).resolve().parent


def _normalize_dist_name(name: str) -> str:
    # PEP 427-compatible wheel name normalization.
    return re.sub(r"[-_.]+", "_", name).lower()


def _load_project_from_pyproject() -> dict:
    merged = dict(DEFAULT_PROJECT)
    pyproject = PROJECT_ROOT / "pyproject.toml"
    if tomllib is None or not pyproject.is_file():
        return merged

    try:
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return merged

    project = data.get("project", {})
    if not isinstance(project, dict):
        return merged

    name = project.get("name")
    version = project.get("version")
    description = project.get("description")
    license_info = project.get("license")
    requires_python = project.get("requires-python")
    dependencies = project.get("dependencies")
    scripts = project.get("scripts")

    if isinstance(name, str) and name.strip():
        merged["name"] = name.strip()
    if isinstance(version, str) and version.strip():
        merged["version"] = version.strip()
    if isinstance(description, str) and description.strip():
        merged["description"] = description.strip()
    if isinstance(license_info, str) and license_info.strip():
        merged["license"] = license_info.strip()
    elif isinstance(license_info, dict):
        text = license_info.get("text")
        file_name = license_info.get("file")
        if isinstance(text, str) and text.strip():
            merged["license"] = text.strip()
        elif isinstance(file_name, str) and file_name.strip():
            merged["license"] = file_name.strip()
    if isinstance(requires_python, str) and requires_python.strip():
        merged["requires_python"] = requires_python.strip()
    if isinstance(dependencies, list):
        merged["dependencies"] = [str(x) for x in dependencies if str(x).strip()]
    if isinstance(scripts, dict) and scripts:
        merged["scripts"] = {
            str(k): str(v) for k, v in scripts.items() if str(k).strip() and str(v).strip()
        }

    return merged


PROJECT = _load_project_from_pyproject()
DIST_NAME = PROJECT["name"]
DIST_NAME_NORMALIZED = _normalize_dist_name(DIST_NAME)
VERSION = PROJECT["version"]
SUMMARY = PROJECT["description"]
LICENSE_TEXT = PROJECT["license"]
PYTHON_REQUIRES = PROJECT["requires_python"]
DEPENDENCIES = PROJECT["dependencies"]
SCRIPT_ENTRIES = PROJECT["scripts"]

PACKAGE_DIR = PROJECT_ROOT / "tnt_deobfuscator"
TOP_LEVEL = "tnt_deobfuscator"
IDA_PLUGIN_SOURCE = PACKAGE_DIR / "ida_plugin.py"
IDA_PLUGIN_FILENAME = "tnt_deobfuscator_ida.py"
LICENSE_SOURCE = PROJECT_ROOT / "LICENSE"


def _dist_info_dir() -> str:
    return f"{DIST_NAME_NORMALIZED}-{VERSION}.dist-info"


def _wheel_filename() -> str:
    return f"{DIST_NAME_NORMALIZED}-{VERSION}-py3-none-any.whl"


def _metadata_text() -> str:
    lines = [
        "Metadata-Version: 2.1\n"
        f"Name: {DIST_NAME}\n"
        f"Version: {VERSION}\n"
        f"Summary: {SUMMARY}\n"
        f"License: {LICENSE_TEXT}\n"
        f"Requires-Python: {PYTHON_REQUIRES}\n"
    ]
    for dep in DEPENDENCIES:
        lines.append(f"Requires-Dist: {dep}\n")
    return "".join(lines)


def _wheel_text() -> str:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: custom-offline-backend\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    )


def _entry_points_text() -> str:
    lines = ["[console_scripts]\n"]
    for name, target in SCRIPT_ENTRIES.items():
        lines.append(f"{name} = {target}\n")
    return "".join(lines)


def _hash_and_size(content: bytes) -> tuple[str, int]:
    digest = hashlib.sha256(content).digest()
    b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={b64}", len(content)


def _iter_package_files() -> list[Path]:
    return sorted(
        p for p in PACKAGE_DIR.rglob("*.py") if p.is_file() and "__pycache__" not in p.parts
    )


def _candidate_ida_plugin_dirs() -> list[Path]:
    forced = os.environ.get("TNT_IDA_PLUGIN_DIR")
    if forced:
        return [Path(forced).expanduser()]

    home = Path.home()
    candidates: list[Path] = []
    if sys.platform.startswith("darwin") or sys.platform.startswith("linux"):
        candidates.append(home / ".idapro" / "plugins")
    elif os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Hex-Rays" / "IDA Pro" / "plugins")
            candidates.append(Path(appdata) / "IDA Pro" / "plugins")
        candidates.append(home / ".idapro" / "plugins")
    else:
        candidates.append(home / ".idapro" / "plugins")

    unique: list[Path] = []
    seen: set[str] = set()
    for item in candidates:
        key = str(item)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _install_ida_plugin_if_possible() -> None:
    if os.environ.get("TNT_DEOBF_SKIP_IDA_PLUGIN_INSTALL") == "1":
        return
    if not IDA_PLUGIN_SOURCE.is_file():
        return

    plugin_data = IDA_PLUGIN_SOURCE.read_bytes()
    for plugin_dir in _candidate_ida_plugin_dirs():
        try:
            plugin_dir.mkdir(parents=True, exist_ok=True)
            dst = plugin_dir / IDA_PLUGIN_FILENAME
            if dst.is_file() and dst.read_bytes() == plugin_data:
                continue
            dst.write_bytes(plugin_data)
            print(f"[tnt-deobfuscator] installed IDA plugin: {dst}")
        except OSError as exc:
            print(f"[tnt-deobfuscator] warning: failed to install IDA plugin to {plugin_dir}: {exc}")


def _build_wheel_file(wheel_directory: str) -> str:
    _install_ida_plugin_if_possible()
    wheel_dir = Path(wheel_directory)
    wheel_dir.mkdir(parents=True, exist_ok=True)
    wheel_name = _wheel_filename()
    wheel_path = wheel_dir / wheel_name
    dist_info = _dist_info_dir()

    records: list[tuple[str, bytes]] = []

    with ZipFile(wheel_path, "w", compression=ZIP_DEFLATED) as zf:
        for src in _iter_package_files():
            arcname = src.relative_to(PROJECT_ROOT).as_posix()
            data = src.read_bytes()
            zf.writestr(arcname, data)
            records.append((arcname, data))

        metadata_path = f"{dist_info}/METADATA"
        metadata_data = _metadata_text().encode("utf-8")
        zf.writestr(metadata_path, metadata_data)
        records.append((metadata_path, metadata_data))

        wheel_meta_path = f"{dist_info}/WHEEL"
        wheel_meta_data = _wheel_text().encode("utf-8")
        zf.writestr(wheel_meta_path, wheel_meta_data)
        records.append((wheel_meta_path, wheel_meta_data))

        entry_points_path = f"{dist_info}/entry_points.txt"
        entry_points_data = _entry_points_text().encode("utf-8")
        zf.writestr(entry_points_path, entry_points_data)
        records.append((entry_points_path, entry_points_data))

        top_level_path = f"{dist_info}/top_level.txt"
        top_level_data = f"{TOP_LEVEL}\n".encode("utf-8")
        zf.writestr(top_level_path, top_level_data)
        records.append((top_level_path, top_level_data))

        if LICENSE_SOURCE.is_file():
            license_path = f"{dist_info}/LICENSE"
            license_data = LICENSE_SOURCE.read_bytes()
            zf.writestr(license_path, license_data)
            records.append((license_path, license_data))

        record_path = f"{dist_info}/RECORD"
        lines = []
        for path, data in records:
            digest, size = _hash_and_size(data)
            lines.append(f"{path},{digest},{size}")
        lines.append(f"{record_path},,")
        record_data = ("\n".join(lines) + "\n").encode("utf-8")
        zf.writestr(record_path, record_data)

    return wheel_name


def _build_editable_wheel_file(wheel_directory: str) -> str:
    _install_ida_plugin_if_possible()
    wheel_dir = Path(wheel_directory)
    wheel_dir.mkdir(parents=True, exist_ok=True)
    wheel_name = _wheel_filename()
    wheel_path = wheel_dir / wheel_name
    dist_info = _dist_info_dir()

    records: list[tuple[str, bytes]] = []

    with ZipFile(wheel_path, "w", compression=ZIP_DEFLATED) as zf:
        pth_path = f"{DIST_NAME_NORMALIZED}.pth"
        pth_data = f"{PROJECT_ROOT}\n".encode("utf-8")
        zf.writestr(pth_path, pth_data)
        records.append((pth_path, pth_data))

        metadata_path = f"{dist_info}/METADATA"
        metadata_data = _metadata_text().encode("utf-8")
        zf.writestr(metadata_path, metadata_data)
        records.append((metadata_path, metadata_data))

        wheel_meta_path = f"{dist_info}/WHEEL"
        wheel_meta_data = _wheel_text().encode("utf-8")
        zf.writestr(wheel_meta_path, wheel_meta_data)
        records.append((wheel_meta_path, wheel_meta_data))

        entry_points_path = f"{dist_info}/entry_points.txt"
        entry_points_data = _entry_points_text().encode("utf-8")
        zf.writestr(entry_points_path, entry_points_data)
        records.append((entry_points_path, entry_points_data))

        top_level_path = f"{dist_info}/top_level.txt"
        top_level_data = f"{TOP_LEVEL}\n".encode("utf-8")
        zf.writestr(top_level_path, top_level_data)
        records.append((top_level_path, top_level_data))

        if LICENSE_SOURCE.is_file():
            license_path = f"{dist_info}/LICENSE"
            license_data = LICENSE_SOURCE.read_bytes()
            zf.writestr(license_path, license_data)
            records.append((license_path, license_data))

        record_path = f"{dist_info}/RECORD"
        lines = []
        for path, data in records:
            digest, size = _hash_and_size(data)
            lines.append(f"{path},{digest},{size}")
        lines.append(f"{record_path},,")
        record_data = ("\n".join(lines) + "\n").encode("utf-8")
        zf.writestr(record_path, record_data)

    return wheel_name


def _write_metadata(metadata_directory: str) -> str:
    _install_ida_plugin_if_possible()
    dist_info = _dist_info_dir()
    out_dir = Path(metadata_directory) / dist_info
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "METADATA").write_text(_metadata_text(), encoding="utf-8")
    (out_dir / "WHEEL").write_text(_wheel_text(), encoding="utf-8")
    (out_dir / "entry_points.txt").write_text(_entry_points_text(), encoding="utf-8")
    (out_dir / "top_level.txt").write_text(f"{TOP_LEVEL}\n", encoding="utf-8")
    if LICENSE_SOURCE.is_file():
        (out_dir / "LICENSE").write_bytes(LICENSE_SOURCE.read_bytes())
    return dist_info


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    return _write_metadata(metadata_directory)


def prepare_metadata_for_build_editable(metadata_directory, config_settings=None):
    return _write_metadata(metadata_directory)


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    return _build_wheel_file(wheel_directory)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    return _build_editable_wheel_file(wheel_directory)
