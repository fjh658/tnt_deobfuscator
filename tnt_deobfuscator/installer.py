"""IDA plugin install/uninstall helpers for tnt-deobfuscator."""

from __future__ import annotations

import os
import sys
from pathlib import Path

IDA_PLUGIN_FILENAME = "tnt_deobfuscator_ida.py"
IDA_PLUGIN_SOURCE_NAME = "ida_plugin.py"

ENV_PLUGIN_DIR = "TNT_IDA_PLUGIN_DIR"
ENV_SKIP_INSTALL = "TNT_DEOBF_SKIP_IDA_PLUGIN_INSTALL"
ENV_LINK_MODE = "TNT_IDA_PLUGIN_LINK_MODE"

LINK_MODE_AUTO = "auto"
LINK_MODE_SYMLINK = "symlink"
LINK_MODE_COPY = "copy"
VALID_LINK_MODES = {LINK_MODE_AUTO, LINK_MODE_SYMLINK, LINK_MODE_COPY}

TEMP_PATH_MARKERS = (
    "pip-build-env-",
    "pip-ephem-wheel-cache",
    "pip-install-",
    "pip-modern-metadata-",
    "pip-req-build-",
)


def _default_plugin_source() -> Path:
    return Path(__file__).resolve().with_name(IDA_PLUGIN_SOURCE_NAME)


def _candidate_ida_plugin_dirs() -> list[Path]:
    forced = os.environ.get(ENV_PLUGIN_DIR)
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


def _path_looks_temporary(path: Path) -> bool:
    text = str(path.resolve()).lower().replace("\\", "/")
    return any(marker in text for marker in TEMP_PATH_MARKERS)


def _plugin_link_mode() -> str:
    raw = os.environ.get(ENV_LINK_MODE, LINK_MODE_AUTO)
    mode = str(raw).strip().lower()
    if mode in VALID_LINK_MODES:
        return mode
    return LINK_MODE_AUTO


def _use_symlink_for_plugin(source: Path, mode: str) -> bool:
    if mode == LINK_MODE_COPY:
        return False
    if mode == LINK_MODE_SYMLINK:
        return True
    return not _path_looks_temporary(source)


def _same_symlink(dst: Path, source: Path) -> bool:
    if not dst.is_symlink():
        return False
    try:
        current_target = dst.resolve(strict=False)
    except OSError:
        return False
    return current_target == source


def _ensure_plugin_symlink(dst: Path, source: Path, *, quiet: bool) -> bool:
    try:
        if _same_symlink(dst, source):
            return True
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        dst.symlink_to(source)
        if not quiet:
            print(f"[tnt-deobfuscator] installed IDA plugin symlink: {dst} -> {source}")
        return True
    except OSError:
        return False


def _ensure_plugin_copy(dst: Path, plugin_data: bytes, *, quiet: bool) -> None:
    if dst.is_symlink():
        dst.unlink()
    elif dst.is_file() and dst.read_bytes() == plugin_data:
        return
    elif dst.exists() and not dst.is_file():
        raise OSError(f"destination exists and is not a file: {dst}")
    dst.write_bytes(plugin_data)
    if not quiet:
        print(f"[tnt-deobfuscator] installed IDA plugin: {dst}")


def install_ida_plugin(
    *,
    source: Path | None = None,
    quiet: bool = False,
) -> list[Path]:
    """Install IDA plugin file into candidate plugin directories.

    Returns plugin paths that exist after installation.
    """
    if os.environ.get(ENV_SKIP_INSTALL) == "1":
        return []

    plugin_source = (source or _default_plugin_source()).resolve()
    if not plugin_source.is_file():
        if not quiet:
            print(f"[tnt-deobfuscator] warning: plugin source not found: {plugin_source}")
        return []

    link_mode = _plugin_link_mode()
    use_symlink = _use_symlink_for_plugin(plugin_source, link_mode)
    plugin_data = plugin_source.read_bytes()
    installed_paths: list[Path] = []

    for plugin_dir in _candidate_ida_plugin_dirs():
        try:
            plugin_dir.mkdir(parents=True, exist_ok=True)
            dst = plugin_dir / IDA_PLUGIN_FILENAME
            if use_symlink and _ensure_plugin_symlink(dst, plugin_source, quiet=quiet):
                installed_paths.append(dst)
                continue
            _ensure_plugin_copy(dst, plugin_data, quiet=quiet)
            if dst.exists() or dst.is_symlink():
                installed_paths.append(dst)
        except OSError as exc:
            if not quiet:
                print(
                    f"[tnt-deobfuscator] warning: failed to install IDA plugin to {plugin_dir}: {exc}"
                )

    return installed_paths


def uninstall_ida_plugin(*, quiet: bool = False) -> list[Path]:
    """Remove installed IDA plugin file from candidate plugin directories."""
    removed: list[Path] = []
    for plugin_dir in _candidate_ida_plugin_dirs():
        dst = plugin_dir / IDA_PLUGIN_FILENAME
        try:
            if dst.is_symlink() or dst.is_file():
                dst.unlink()
                removed.append(dst)
                if not quiet:
                    print(f"[tnt-deobfuscator] removed IDA plugin: {dst}")
            elif dst.exists() and not quiet:
                print(
                    f"[tnt-deobfuscator] warning: plugin path exists but is not a file/symlink: {dst}"
                )
        except OSError as exc:
            if not quiet:
                print(
                    f"[tnt-deobfuscator] warning: failed to remove IDA plugin at {dst}: {exc}"
                )
    return removed

