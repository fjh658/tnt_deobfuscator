"""IDA plugin bridge for tnt-deobfuscator.

The plugin is intentionally lightweight: it invokes the external CLI tool
`tnt-deobfuscator` against the currently loaded input file.
"""

import os
import shlex
import subprocess

import ida_kernwin

try:
    import ida_nalt
except Exception:  # pragma: no cover - depends on IDA runtime
    ida_nalt = None

try:
    import idc
except Exception:  # pragma: no cover - depends on IDA runtime
    idc = None

import idaapi


PLUGIN_NAME = "TNT Deobfuscator"
DEFAULT_CLI = "tnt-deobfuscator"
VALID_MODES = {"static", "dynamic"}
VALID_ARCHES = {"all", "x86_64", "arm64"}


def _msg(text: str) -> None:
    ida_kernwin.msg(f"[{PLUGIN_NAME}] {text}\n")


def _get_input_path() -> str:
    if ida_nalt is not None:
        try:
            path = ida_nalt.get_input_file_path()
            if path:
                return path
        except Exception:
            pass
    if idc is not None:
        try:
            path = idc.get_input_file_path()
            if path:
                return path
        except Exception:
            pass
    return ""


def _normalize_mode(value: str | None) -> str | None:
    if not value:
        return None
    mode = value.strip().lower()
    if mode in VALID_MODES:
        return mode
    return None


def _normalize_arch(value: str | None) -> str | None:
    if not value:
        return None
    arch = value.strip().lower()
    if arch in VALID_ARCHES:
        return arch
    return None


def _prompt_mode(default_mode: str) -> str | None:
    if os.environ.get("TNT_DEOBF_NO_MODE_PROMPT") == "1":
        return default_mode

    prompt = "Mode (static / dynamic). Leave empty for default."
    for _ in range(2):
        answer = ida_kernwin.ask_str(default_mode, 0, prompt)
        if answer is None:
            return None
        if not answer.strip():
            return default_mode
        mode = _normalize_mode(answer)
        if mode:
            return mode
        ida_kernwin.warning("Invalid mode. Expected: static or dynamic.")
    return None


def _detect_ida_arch() -> str:
    try:
        info = idaapi.get_inf_structure()
        procname = str(getattr(info, "procname", "")).lower()
        is_64bit = bool(info.is_64bit())
    except Exception:
        return "all"

    if is_64bit and procname in {"metapc", "pc", "x86"}:
        return "x86_64"
    if is_64bit and procname in {"arm", "aarch64"}:
        return "arm64"
    return "all"


def _prompt_arch(default_arch: str) -> str | None:
    if os.environ.get("TNT_DEOBF_NO_ARCH_PROMPT") == "1":
        return default_arch

    prompt = "Arch (all / x86_64 / arm64). Leave empty for default."
    for _ in range(2):
        answer = ida_kernwin.ask_str(default_arch, 0, prompt)
        if answer is None:
            return None
        if not answer.strip():
            return default_arch
        arch = _normalize_arch(answer)
        if arch:
            return arch
        ida_kernwin.warning("Invalid arch. Expected: all, x86_64, or arm64.")
    return None


def _prompt_dynamic_args(default_args: str) -> str | None:
    if os.environ.get("TNT_DEOBF_NO_DYNAMIC_PROMPT") == "1":
        return default_args
    prompt = (
        "Dynamic mode extra args (optional), e.g. "
        "--emu-timeout-ms 30000 --emu-max-insn 2000000"
    )
    answer = ida_kernwin.ask_str(default_args, 0, prompt)
    if answer is None:
        return None
    return answer.strip()


def _build_command(
    input_path: str,
    output_path: str,
    mode: str,
    arch: str,
    dynamic_args: str,
) -> list[str]:
    raw_cli = os.environ.get("TNT_DEOBF_CLI", DEFAULT_CLI).strip()
    cli_parts = shlex.split(raw_cli) if raw_cli else [DEFAULT_CLI]
    cmd = [*cli_parts, "-i", input_path, "-o", output_path, "--arch", arch, "--mode", mode]
    if mode == "dynamic" and dynamic_args:
        cmd.extend(shlex.split(dynamic_args))
    extra = os.environ.get("TNT_DEOBF_ARGS", "").strip()
    if extra:
        cmd.extend(shlex.split(extra))
    return cmd


class TntDeobfuscatorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Run tnt-deobfuscator against current input file"
    help = (
        "Set TNT_DEOBF_CLI, TNT_DEOBF_ARGS, TNT_DEOBF_MODE, TNT_DEOBF_ARCH, "
        "TNT_DEOBF_DYNAMIC_ARGS, TNT_DEOBF_NO_*_PROMPT environment variables "
        "to customize invocation."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        _msg("loaded.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        input_path = _get_input_path()
        if not input_path:
            ida_kernwin.warning("Input file path is unavailable in this IDA session.")
            return

        default_out = f"{input_path}.deobf"
        output_path = ida_kernwin.ask_file(1, "*", f"Output file [{default_out}]")
        if not output_path:
            output_path = default_out

        env_mode = _normalize_mode(os.environ.get("TNT_DEOBF_MODE"))
        mode = _prompt_mode(env_mode or "static")
        if mode is None:
            _msg("cancelled.")
            return

        env_arch = _normalize_arch(os.environ.get("TNT_DEOBF_ARCH"))
        arch = _prompt_arch(env_arch or _detect_ida_arch())
        if arch is None:
            _msg("cancelled.")
            return

        dynamic_args_default = os.environ.get("TNT_DEOBF_DYNAMIC_ARGS", "").strip()
        dynamic_args = ""
        if mode == "dynamic":
            dynamic_args = _prompt_dynamic_args(dynamic_args_default)
            if dynamic_args is None:
                _msg("cancelled.")
                return

        cmd = _build_command(input_path, output_path, mode, arch, dynamic_args)
        _msg("running: " + " ".join(shlex.quote(part) for part in cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        except OSError as exc:
            ida_kernwin.warning(f"Failed to launch {cmd[0]}: {exc}")
            return

        if proc.stdout:
            _msg(proc.stdout.rstrip())
        if proc.stderr:
            _msg(proc.stderr.rstrip())

        if proc.returncode == 0:
            ida_kernwin.info(f"Deobfuscated file written to:\n{output_path}")
        else:
            ida_kernwin.warning(
                f"tnt-deobfuscator failed with exit code {proc.returncode}. "
                "Check Output window for details."
            )

    def term(self):
        pass


def PLUGIN_ENTRY():
    return TntDeobfuscatorPlugin()
