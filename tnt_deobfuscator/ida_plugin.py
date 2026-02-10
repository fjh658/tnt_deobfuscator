"""IDA plugin bridge and repair automation for tnt-deobfuscator.

The plugin can do two things:
1) invoke the external `tnt-deobfuscator` CLI for file-level processing
2) repair the current IDB after loading a deobfuscated binary
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_kernwin
import idaapi
import ida_name
import ida_nalt
import ida_segment
import idautils
import idc


PLUGIN_NAME = "TNT Deobfuscator"
DEFAULT_CLI = "tnt-deobfuscator"
VALID_MODES = {"static", "dynamic"}
VALID_ARCHES = {"all", "x86_64", "arm64"}
VALID_ACTIONS = {"repair", "deobfuscate", "both"}
VALID_REPAIR_PROFILES = {"auto", "analysis", "runnable"}
MIN_IDA_VERSION = (8, 3)
REPROCESS_NAME_HINTS = (".deobf", ".strfix", ".analysis", ".runnable")
REPAIR_BOOTSTRAP_NAME = "init_runtime_decrypt_and_bootstrap"
HEXRAYS_READY: bool | None = None

MEMCPY_LITERAL_RE = re.compile(
    r"memcpy\s*\(\s*[^,]+,\s*\"((?:[^\"\\]|\\.)*)\"\s*,",
    re.DOTALL,
)
HEX_BYTE_RE = re.compile(r"\^\s*0x([0-9a-fA-F]{1,2})")


def _name_flag(flag_name: str) -> int:
    for mod in (ida_name, idaapi):
        try:
            value = getattr(mod, flag_name)
        except Exception:
            continue
        if isinstance(value, int):
            return int(value)
    return 0


SN_CHECK_FLAG = _name_flag("SN_CHECK")
SN_NOWARN_FLAG = _name_flag("SN_NOWARN")


@dataclass
class LiteralInfo:
    text: str
    source: str
    xor_key: int | None = None


@dataclass
class WrapperRecord:
    wrapper_ea: int
    literal_func_ea: int
    context: str = "unknown"
    call_sites: list[int] = field(default_factory=list)


@dataclass
class RepairStats:
    bootstrap_ea: int | None = None
    wrappers_seen: int = 0
    wrappers_renamed: int = 0
    literals_resolved: int = 0
    comments_added: int = 0
    data_notes_added: int = 0
    strings_created: int = 0
    profile: str = "runnable"
    skipped: bool = False


def _msg(text: str) -> None:
    ida_kernwin.msg(f"[{PLUGIN_NAME}] {text}\n")


def _warn(text: str) -> None:
    ida_kernwin.warning(text)


def _ida_version_tuple() -> tuple[int, int]:
    try:
        raw = idaapi.get_kernel_version()
    except Exception:
        return (0, 0)
    m = re.match(r"^\s*(\d+)\.(\d+)", str(raw))
    if not m:
        return (0, 0)
    return int(m.group(1)), int(m.group(2))


def _ida_version_text(ver: tuple[int, int]) -> str:
    return f"{ver[0]}.{ver[1]}"


def _ask_yes_no(prompt: str, default_no: bool = True) -> bool:
    default_btn = ida_kernwin.ASKBTN_NO if default_no else ida_kernwin.ASKBTN_YES
    answer = ida_kernwin.ask_yn(default_btn, prompt)
    return answer == ida_kernwin.ASKBTN_YES


def _looks_filename_stage1_processed(path_text: str) -> bool:
    name = Path(path_text).name.lower()
    return any(tag in name for tag in REPROCESS_NAME_HINTS)


def _get_input_path() -> str:
    try:
        path = ida_nalt.get_input_file_path()
        if path:
            return path
    except Exception:
        pass
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


def _normalize_action(value: str | None) -> str | None:
    if not value:
        return None
    action = value.strip().lower()
    if action in {"deobf", "deobfuscate"}:
        return "deobfuscate"
    if action in VALID_ACTIONS:
        return action
    return None


def _prompt_action(default_action: str) -> str | None:
    if os.environ.get("TNT_DEOBF_NO_ACTION_PROMPT") == "1":
        return default_action

    return _prompt_readonly_dropdown(
        title="TNT Deobfuscator",
        prompt="Action",
        options=["repair", "deobfuscate", "both"],
        default_value=default_action,
    )


def _prompt_mode(default_mode: str) -> str | None:
    if os.environ.get("TNT_DEOBF_NO_MODE_PROMPT") == "1":
        return default_mode

    return _prompt_readonly_dropdown(
        title="TNT Deobfuscator",
        prompt="Mode",
        options=["static", "dynamic"],
        default_value=default_mode,
    )


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

    return _prompt_readonly_dropdown(
        title="TNT Deobfuscator",
        prompt="Arch",
        options=["all", "x86_64", "arm64"],
        default_value=default_arch,
    )


def _prompt_readonly_dropdown(
    title: str,
    prompt: str,
    options: list[str],
    default_value: str,
) -> str | None:
    if not options:
        return None

    try:
        default_index = options.index(default_value)
    except ValueError:
        default_index = 0

    F = ida_kernwin.Form

    class _ChoiceForm(F):
        def __init__(self):
            F.__init__(
                self,
                f"""BUTTON YES* OK
BUTTON CANCEL Cancel
{title}

<{prompt}:{{choice}}>
""",
                {
                    "choice": F.DropdownListControl(
                        items=options,
                        readonly=True,
                        selval=default_index,
                    ),
                },
            )

    form = _ChoiceForm()
    form, _ = form.Compile()
    ok = form.Execute()
    if ok != 1:
        form.Free()
        return None

    try:
        index = int(form.choice.value)
    except Exception:
        index = default_index
    finally:
        form.Free()

    if index < 0 or index >= len(options):
        return options[default_index]
    return options[index]


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


def _split_args(raw: str, field_name: str) -> list[str]:
    value = (raw or "").strip()
    if not value:
        return []
    try:
        return shlex.split(value)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {exc}") from exc


def _normalize_repair_profile(value: str | None) -> str | None:
    if not value:
        return None
    profile = value.strip().lower()
    if profile in VALID_REPAIR_PROFILES:
        return profile
    return None


def _resolve_repair_profile(input_path: str) -> str:
    env_profile = _normalize_repair_profile(os.environ.get("TNT_DEOBF_REPAIR_PROFILE"))
    if env_profile and env_profile != "auto":
        return env_profile

    name = Path(input_path).name.lower()
    if ".analysis" in name:
        return "analysis"
    if ".runnable" in name:
        return "runnable"
    return "runnable"


def _build_command(
    input_path: str,
    output_path: str,
    mode: str,
    arch: str,
    dynamic_args: str,
    force_reprocess: bool = False,
) -> list[str]:
    raw_cli = os.environ.get("TNT_DEOBF_CLI", DEFAULT_CLI).strip()
    cli_parts = _split_args(raw_cli, "TNT_DEOBF_CLI") if raw_cli else [DEFAULT_CLI]
    cmd = [*cli_parts, mode, "-i", input_path, "-o", output_path, "--arch", arch]
    if mode == "dynamic" and dynamic_args:
        cmd.extend(_split_args(dynamic_args, "dynamic args"))
    if force_reprocess:
        cmd.append("--force-reprocess")
    extra = os.environ.get("TNT_DEOBF_ARGS", "").strip()
    if extra:
        cmd.extend(_split_args(extra, "TNT_DEOBF_ARGS"))
    return cmd


def _run_cli(input_path: str) -> tuple[bool, str | None]:
    default_out = f"{input_path}.deobf"
    output_path = ida_kernwin.ask_file(1, "*", f"Output file [{default_out}]")
    if output_path is None:
        _msg("cancelled.")
        return False, None
    if not output_path:
        output_path = default_out

    env_mode = _normalize_mode(os.environ.get("TNT_DEOBF_MODE"))
    mode = _prompt_mode(env_mode or "static")
    if mode is None:
        _msg("cancelled.")
        return False, None

    env_arch = _normalize_arch(os.environ.get("TNT_DEOBF_ARCH"))
    arch = _prompt_arch(env_arch or _detect_ida_arch())
    if arch is None:
        _msg("cancelled.")
        return False, None

    dynamic_args_default = os.environ.get("TNT_DEOBF_DYNAMIC_ARGS", "").strip()
    dynamic_args = ""
    if mode == "dynamic":
        dynamic_args = _prompt_dynamic_args(dynamic_args_default)
        if dynamic_args is None:
            _msg("cancelled.")
            return False, None

    force_reprocess = os.environ.get("TNT_DEOBF_FORCE_REPROCESS") == "1"
    if not force_reprocess and _looks_filename_stage1_processed(input_path):
        if not _ask_yes_no(
            "Input filename looks already first-stage processed.\n"
            "Running first-stage again may flip patched regions.\n"
            "Continue anyway?",
            default_no=True,
        ):
            _msg("deobfuscation step skipped by user.")
            return True, None
        force_reprocess = True

    try:
        cmd = _build_command(
            input_path=input_path,
            output_path=output_path,
            mode=mode,
            arch=arch,
            dynamic_args=dynamic_args,
            force_reprocess=force_reprocess,
        )
    except ValueError as exc:
        _warn(str(exc))
        return False, output_path

    timeout_sec: float | None = None
    timeout_raw = os.environ.get("TNT_DEOBF_TIMEOUT_SEC", "").strip()
    if timeout_raw:
        try:
            timeout_val = float(timeout_raw)
        except ValueError:
            _warn(f"Invalid TNT_DEOBF_TIMEOUT_SEC: {timeout_raw!r}")
            return False, output_path
        if timeout_val > 0:
            timeout_sec = timeout_val

    _msg("running: " + " ".join(shlex.quote(part) for part in cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
        )
    except OSError as exc:
        _warn(f"Failed to launch {cmd[0]}: {exc}")
        return False, output_path
    except subprocess.TimeoutExpired:
        _warn(
            "tnt-deobfuscator timed out. "
            "Increase TNT_DEOBF_TIMEOUT_SEC or run from terminal for long tasks."
        )
        return False, output_path

    if proc.stdout:
        _msg(proc.stdout.rstrip())
    if proc.stderr:
        _msg(proc.stderr.rstrip())

    if proc.returncode == 0:
        ida_kernwin.info(f"Deobfuscated file written to:\n{output_path}")
        return True, output_path

    _warn(
        f"tnt-deobfuscator failed with exit code {proc.returncode}. "
        "Check Output window for details."
    )
    return False, output_path


def _iter_functions() -> list[int]:
    try:
        return list(idautils.Functions())
    except Exception:
        return []


def _iter_func_items(func_ea: int) -> list[int]:
    try:
        return list(idautils.FuncItems(func_ea))
    except Exception:
        return []


def _func_size(func_ea: int) -> int:
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return 0
    return max(0, int(func.end_ea - func.start_ea))


def _normalize_name(name: str) -> str:
    n = (name or "").lower()
    n = n.lstrip("_")
    if n.startswith("j_"):
        n = n[2:]
    if n.startswith("imp_"):
        n = n[4:]
    return n


def _name_contains(name: str, needle: str) -> bool:
    return needle in _normalize_name(name)


def _safe_name(ea: int) -> str:
    try:
        return idc.get_name(ea, ida_name.GN_VISIBLE) or ""
    except Exception:
        return ""


def _is_call_mnemonic(mnemonic: str) -> bool:
    m = mnemonic.lower()
    return m in {"call", "bl", "blr"}


def _resolve_call_target(insn_ea: int) -> int | None:
    try:
        mnem = idc.print_insn_mnem(insn_ea)
    except Exception:
        return None
    if not _is_call_mnemonic(mnem):
        return None
    try:
        op_type = idc.get_operand_type(insn_ea, 0)
        if op_type in {idc.o_near, idc.o_far, idc.o_mem, idc.o_imm}:
            target = int(idc.get_operand_value(insn_ea, 0))
            if target not in {0, idc.BADADDR}:
                return target
    except Exception:
        return None
    return None


def _collect_call_sequence(func_ea: int) -> list[tuple[int, int, str]]:
    out: list[tuple[int, int, str]] = []
    for insn_ea in _iter_func_items(func_ea):
        target = _resolve_call_target(insn_ea)
        if target is None:
            continue
        out.append((insn_ea, target, _safe_name(target)))
    return out


def _detect_bootstrap_function() -> int | None:
    best_ea: int | None = None
    best_score = -1
    for func_ea in _iter_functions():
        calls = _collect_call_sequence(func_ea)
        if len(calls) < 15:
            continue

        score = 0
        seen_getclass = False
        seen_sel = False
        seen_msgsend = False

        for _, _, callee_name in calls:
            if _name_contains(callee_name, "objc_getclass"):
                seen_getclass = True
                score += 7
            elif _name_contains(callee_name, "sel_registername"):
                seen_sel = True
                score += 7
            elif _name_contains(callee_name, "objc_msgsend"):
                seen_msgsend = True
                score += 6
            elif _name_contains(callee_name, "mprotect"):
                score += 3
            elif _name_contains(callee_name, "vm_protect"):
                score += 3

        if seen_getclass and seen_sel and seen_msgsend:
            score += 12
        if score > best_score:
            best_score = score
            best_ea = func_ea

    if best_score < 12:
        return None
    return best_ea


def _collect_small_wrappers() -> dict[int, int]:
    wrappers: dict[int, int] = {}
    for func_ea in _iter_functions():
        size = _func_size(func_ea)
        if size <= 0 or size > 0x30:
            continue
        calls = []
        for insn_ea in _iter_func_items(func_ea):
            target = _resolve_call_target(insn_ea)
            if target is not None:
                calls.append(target)
        if len(calls) != 1:
            continue
        target = calls[0]
        if target == func_ea:
            continue
        if ida_funcs.get_func(target) is None:
            continue
        wrappers[func_ea] = target
    return wrappers


def _parse_c_string_literal(raw: str) -> bytes:
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\":
            out.append(ord(ch) & 0xFF)
            i += 1
            continue
        i += 1
        if i >= n:
            break
        esc = raw[i]
        i += 1
        if esc == "x":
            hex_digits = ""
            while i < n and raw[i] in "0123456789abcdefABCDEF" and len(hex_digits) < 2:
                hex_digits += raw[i]
                i += 1
            if hex_digits:
                out.append(int(hex_digits, 16))
            else:
                out.append(ord("x"))
            continue
        if esc in "01234567":
            oct_digits = esc
            for _ in range(2):
                if i < n and raw[i] in "01234567":
                    oct_digits += raw[i]
                    i += 1
                else:
                    break
            out.append(int(oct_digits, 8) & 0xFF)
            continue
        mapping = {
            "n": 0x0A,
            "r": 0x0D,
            "t": 0x09,
            "\\": 0x5C,
            "\"": 0x22,
            "'": 0x27,
            "0": 0x00,
        }
        out.append(mapping.get(esc, ord(esc) & 0xFF))
    return bytes(out)


def _bytes_to_text(raw: bytes) -> str:
    b = raw.split(b"\x00", 1)[0]
    if not b:
        return ""
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("latin-1", "ignore")


def _looks_meaningful_text(text: str) -> bool:
    if not text or len(text) < 3:
        return False
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in text):
        return False
    alnum = sum(ch.isalnum() for ch in text)
    return alnum >= 2


def _score_text(text: str) -> int:
    return sum(ch.isalnum() for ch in text) + sum(ch in "_:/.- " for ch in text)


def _looks_likely_obfuscated_literal(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    # Encoded TNT literals frequently contain these punctuation characters.
    punct = sum(ch in "[]@\\^`{}~" for ch in t)
    if punct >= 2:
        return True
    letters = sum(ch.isalpha() for ch in t)
    vowels = sum(ch.lower() in "aeiou" for ch in t if ch.isalpha())
    if letters >= 8 and vowels == 0:
        return True
    return False


def _decode_with_single_byte_xor(raw: bytes, key: int) -> str:
    if not raw:
        return ""
    decoded = bytes((b ^ key) & 0xFF for b in raw)
    return _bytes_to_text(decoded)


def _try_single_byte_xor(raw: bytes) -> tuple[str, int] | None:
    best: tuple[str, int, int] | None = None
    for key in range(1, 256):
        text = _decode_with_single_byte_xor(raw, key)
        if not _looks_meaningful_text(text):
            continue
        score = _score_text(text)
        if best is None or score > best[2]:
            best = (text, key, score)
    if best is None:
        return None
    return best[0], best[1]


def _extract_literal_from_decompiler(func_ea: int) -> LiteralInfo | None:
    global HEXRAYS_READY
    try:
        if HEXRAYS_READY is None:
            HEXRAYS_READY = bool(ida_hexrays.init_hexrays_plugin())
        if not HEXRAYS_READY:
            return None
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return None
    if cfunc is None:
        return None

    text = str(cfunc)
    match = MEMCPY_LITERAL_RE.search(text)
    if not match:
        return None

    raw_lit = _parse_c_string_literal(match.group(1))
    plain = _bytes_to_text(raw_lit)

    keys = [int(m.group(1), 16) for m in HEX_BYTE_RE.finditer(text)]
    if keys:
        xor_key = max(set(keys), key=keys.count)
        decoded_text = _decode_with_single_byte_xor(raw_lit, xor_key)
        if _looks_meaningful_text(decoded_text):
            if (
                not _looks_meaningful_text(plain)
                or _looks_likely_obfuscated_literal(plain)
                or decoded_text != plain
            ):
                return LiteralInfo(text=decoded_text, source="decompile-xor", xor_key=xor_key)

    if _looks_meaningful_text(plain):
        return LiteralInfo(text=plain, source="decompile")

    if keys:
        xor_key = max(set(keys), key=keys.count)
        decoded_text = _decode_with_single_byte_xor(raw_lit, xor_key)
        if _looks_meaningful_text(decoded_text):
            return LiteralInfo(text=decoded_text, source="decompile-xor", xor_key=xor_key)

    fallback = plain.strip()
    if fallback:
        return LiteralInfo(text=fallback, source="decompile-raw")
    return None


def _is_data_segment_ea(ea: int) -> bool:
    seg = ida_segment.getseg(ea)
    if seg is None:
        return False
    try:
        name = ida_segment.get_segm_name(seg).lower()
    except Exception:
        name = ""
    if "__text" in name or "text" == name:
        return False
    return True


def _read_c_string_bytes(ea: int, max_len: int = 128) -> bytes:
    out = bytearray()
    for i in range(max_len):
        b = ida_bytes.get_byte(ea + i)
        if b < 0:
            break
        if b == 0:
            break
        out.append(b & 0xFF)
    return bytes(out)


def _collect_func_xor_immediates(func_ea: int) -> dict[int, int]:
    counts: dict[int, int] = {}
    for insn_ea in _iter_func_items(func_ea):
        try:
            mnem = idc.print_insn_mnem(insn_ea).lower()
        except Exception:
            continue
        if "xor" not in mnem and "eor" not in mnem:
            continue
        for op_idx in (0, 1, 2):
            try:
                op_type = idc.get_operand_type(insn_ea, op_idx)
            except Exception:
                continue
            if op_type != idc.o_imm:
                continue
            try:
                imm = int(idc.get_operand_value(insn_ea, op_idx)) & 0xFF
            except Exception:
                continue
            if imm == 0:
                continue
            counts[imm] = counts.get(imm, 0) + 1
    return counts


def _infer_xor_key_from_function(func_ea: int) -> int | None:
    counts = _collect_func_xor_immediates(func_ea)
    if not counts:
        return None
    if len(counts) == 1:
        return next(iter(counts))
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    (top_key, top_count), (_, second_count) = ranked[0], ranked[1]
    if top_count >= 2 and top_count > second_count:
        return top_key
    return None


def _extract_literal_from_data_refs(func_ea: int) -> LiteralInfo | None:
    xor_key_hint = _infer_xor_key_from_function(func_ea)
    refs_seen: set[int] = set()
    for insn_ea in _iter_func_items(func_ea):
        try:
            data_refs = list(idautils.DataRefsFrom(insn_ea))
        except Exception:
            data_refs = []
        for ref in data_refs:
            if ref in refs_seen:
                continue
            refs_seen.add(ref)
            if not _is_data_segment_ea(ref):
                continue

            plain_raw = _read_c_string_bytes(ref, 512)
            if plain_raw:
                plain_text = _bytes_to_text(plain_raw)
                if _looks_meaningful_text(plain_text):
                    return LiteralInfo(text=plain_text, source="data-ref")
                if xor_key_hint is not None:
                    hint_text = _decode_with_single_byte_xor(plain_raw, xor_key_hint)
                    if _looks_meaningful_text(hint_text):
                        return LiteralInfo(
                            text=hint_text,
                            source="data-ref-func-xor",
                            xor_key=xor_key_hint,
                        )
                candidate = _try_single_byte_xor(plain_raw)
                if candidate is not None:
                    text, key = candidate
                    return LiteralInfo(text=text, source="data-ref-xor", xor_key=key)

            probe = ida_bytes.get_bytes(ref, 512) or b""
            if not probe:
                continue
            if xor_key_hint is not None:
                hint_text = _decode_with_single_byte_xor(probe, xor_key_hint)
                if _looks_meaningful_text(hint_text):
                    return LiteralInfo(
                        text=hint_text,
                        source="data-ref-func-xor",
                        xor_key=xor_key_hint,
                    )
            candidate = _try_single_byte_xor(probe)
            if candidate is not None:
                text, key = candidate
                if _looks_meaningful_text(text):
                    return LiteralInfo(text=text, source="data-ref-xor", xor_key=key)
    return None


def _extract_literal(func_ea: int, cache: dict[int, LiteralInfo | None]) -> LiteralInfo | None:
    if func_ea in cache:
        return cache[func_ea]
    decompile_info = _extract_literal_from_decompiler(func_ea)
    dataref_info = _extract_literal_from_data_refs(func_ea)
    info = decompile_info
    if info is None:
        info = dataref_info
    elif dataref_info is not None and dataref_info.text != info.text:
        dataref_has_xor = "xor" in dataref_info.source
        decompile_has_xor = "xor" in info.source
        if dataref_has_xor and not decompile_has_xor:
            info = dataref_info
        elif _score_text(dataref_info.text) > (_score_text(info.text) + 2):
            info = dataref_info
    cache[func_ea] = info
    return info


def _sanitize_token(text: str, max_len: int = 56) -> str:
    token = re.sub(r"[^0-9A-Za-z]+", "_", text).strip("_")
    if not token:
        token = "unknown"
    if token[0].isdigit():
        token = f"n_{token}"
    if len(token) > max_len:
        token = token[:max_len].rstrip("_")
    return token


def _classify_literal(text: str, context: str) -> tuple[str, str]:
    literal = (text or "").strip()
    if not literal:
        return "str", "unknown"

    if literal.startswith("__"):
        return "macho", _sanitize_token(literal)

    if context == "class":
        return "class", _sanitize_token(literal)
    if context == "selector":
        return "sel", _sanitize_token(literal)

    if ":" in literal:
        return "sel", _sanitize_token(literal)
    if literal.startswith("NS") and len(literal) > 2 and literal[2].isalpha():
        return "class", _sanitize_token(literal)
    if "%" in literal:
        return "fmt", _sanitize_token(literal)
    if "/" in literal:
        return "path", _sanitize_token(literal)
    if re.fullmatch(r"[A-Z0-9_]+", literal):
        return "env", _sanitize_token(literal)
    if " " in literal:
        return "value", _sanitize_token(literal)
    if literal and literal[0].isupper():
        return "key", _sanitize_token(literal)
    return "str", _sanitize_token(literal)


def _make_name(prefix: str, kind: str, token: str) -> str:
    return f"{prefix}_{kind}_{token}"


def _set_name(ea: int, preferred: str) -> str | None:
    base = preferred[:120]
    if not base:
        return None

    current = _safe_name(ea)
    if current == base or current.startswith(f"{base}_"):
        return current

    flags = SN_CHECK_FLAG | SN_NOWARN_FLAG
    for idx in range(100):
        name = base if idx == 0 else f"{base}_{idx}"
        existing = _named_ea(name)
        if existing != idc.BADADDR and existing != ea:
            continue
        if idaapi.set_name(ea, name, flags):
            return name
    return None


def _set_comment(ea: int, text: str) -> bool:
    try:
        return bool(idc.set_cmt(ea, text, 0))
    except Exception:
        return False


def _ensure_function(ea: int) -> bool:
    if ida_funcs.get_func(ea) is not None:
        return True
    try:
        idc.create_insn(ea)
    except Exception:
        pass
    try:
        return bool(ida_funcs.add_func(ea, idc.BADADDR))
    except Exception:
        return False


def _infer_context(calls: list[tuple[int, int, str]], index: int) -> str:
    for j in range(index + 1, min(index + 4, len(calls))):
        callee_name = calls[j][2]
        if _name_contains(callee_name, "objc_getclass"):
            return "class"
        if _name_contains(callee_name, "sel_registername"):
            return "selector"
    return "unknown"


def _collect_wrapper_records(
    bootstrap_ea: int,
    wrappers: dict[int, int],
) -> dict[int, WrapperRecord]:
    records: dict[int, WrapperRecord] = {}
    calls = _collect_call_sequence(bootstrap_ea)
    for idx, (call_ea, target, _) in enumerate(calls):
        literal_func = wrappers.get(target)
        if literal_func is None:
            continue
        record = records.get(target)
        if record is None:
            record = WrapperRecord(wrapper_ea=target, literal_func_ea=literal_func)
            records[target] = record
        record.call_sites.append(call_ea)
        ctx = _infer_context(calls, idx)
        if record.context == "unknown" and ctx != "unknown":
            record.context = ctx
    return records


def _create_string(ea: int) -> bool:
    try:
        if hasattr(idc, "get_strlit_contents"):
            existing = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
            if existing:
                return False
        return bool(idc.create_strlit(ea, idc.BADADDR))
    except Exception:
        return False


def _annotate_literal_refs(func_ea: int, literal: str, create_strings: bool) -> tuple[int, int]:
    created = 0
    noted = 0
    refs_seen: set[int] = set()
    literal_bytes = literal.encode("utf-8", "ignore")

    for insn_ea in _iter_func_items(func_ea):
        try:
            data_refs = list(idautils.DataRefsFrom(insn_ea))
        except Exception:
            data_refs = []
        for ref in data_refs:
            if ref in refs_seen:
                continue
            refs_seen.add(ref)
            if not _is_data_segment_ea(ref):
                continue

            if create_strings and literal_bytes:
                raw = ida_bytes.get_bytes(ref, len(literal_bytes))
                if raw == literal_bytes and _create_string(ref):
                    created += 1

            if _set_comment(ref, f"decoded literal: {literal}"):
                noted += 1
    return created, noted


def _named_ea(name: str) -> int:
    try:
        return int(idc.get_name_ea_simple(name))
    except Exception:
        return idc.BADADDR


def _count_named_funcs(prefix: str, stop_at: int = 64) -> int:
    count = 0
    for func_ea in _iter_functions():
        if _safe_name(func_ea).startswith(prefix):
            count += 1
            if count >= stop_at:
                break
    return count


def _repair_markers_present() -> tuple[bool, int]:
    bootstrap_ea = _named_ea(REPAIR_BOOTSTRAP_NAME)
    if bootstrap_ea == idc.BADADDR:
        return False, idc.BADADDR

    named_wrappers = _count_named_funcs("get_str_", stop_at=8)
    named_literals = _count_named_funcs("strlit_", stop_at=8)
    return (named_wrappers >= 3 or named_literals >= 3), bootstrap_ea


def _run_repair(input_path: str) -> RepairStats:
    stats = RepairStats()
    profile = _resolve_repair_profile(input_path)
    stats.profile = profile
    create_strings = profile != "analysis"

    force_repair = os.environ.get("TNT_DEOBF_FORCE_REPAIR") == "1"
    if not force_repair:
        already, marker_ea = _repair_markers_present()
        if already:
            if not _ask_yes_no(
                "Repair markers are already present in current IDB.\n"
                "Run second-stage repair again?",
                default_no=True,
            ):
                stats.bootstrap_ea = marker_ea if marker_ea != idc.BADADDR else None
                stats.skipped = True
                return stats

    ida_auto.auto_wait()

    bootstrap_ea = _detect_bootstrap_function()
    stats.bootstrap_ea = bootstrap_ea
    if bootstrap_ea is None:
        _warn("Unable to locate bootstrap function. Try analyzing all code and rerun.")
        return stats

    _ensure_function(bootstrap_ea)
    _set_name(bootstrap_ea, "init_runtime_decrypt_and_bootstrap")
    _set_comment(
        bootstrap_ea,
        "Primary runtime bootstrap: code patching + Objective-C selector/class setup.",
    )

    wrappers = _collect_small_wrappers()
    records = _collect_wrapper_records(bootstrap_ea, wrappers)
    stats.wrappers_seen = len(records)
    if not records:
        _warn("No wrapper->literal function pairs found near bootstrap.")
        return stats

    literal_cache: dict[int, LiteralInfo | None] = {}
    for wrapper_ea, rec in sorted(records.items()):
        _ensure_function(wrapper_ea)
        _ensure_function(rec.literal_func_ea)
        info = _extract_literal(rec.literal_func_ea, literal_cache)

        if info is None or not info.text:
            kind = "str"
            token = f"ea_{rec.literal_func_ea:x}"
            literal_text = token
        else:
            kind, token = _classify_literal(info.text, rec.context)
            literal_text = info.text
            stats.literals_resolved += 1

        literal_name = _make_name("strlit", kind, token)
        wrapper_name = _make_name("get_str", kind, token)

        if _set_name(rec.literal_func_ea, literal_name):
            pass
        if _set_name(wrapper_ea, wrapper_name):
            stats.wrappers_renamed += 1

        if info is not None:
            comment = f"literal[{info.source}] => {literal_text}"
            if info.xor_key is not None:
                comment += f" (xor=0x{info.xor_key:02x})"
            if _set_comment(rec.literal_func_ea, comment):
                stats.comments_added += 1

            created, noted = _annotate_literal_refs(
                rec.literal_func_ea,
                literal_text,
                create_strings=create_strings,
            )
            stats.strings_created += created
            stats.data_notes_added += noted

        for call_ea in rec.call_sites:
            if _set_comment(call_ea, f"{wrapper_name} -> {literal_text}"):
                stats.comments_added += 1

    ida_auto.auto_wait()
    return stats


class TntDeobfuscatorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Run tnt-deobfuscator and/or repair current IDB"
    help = (
        "Set TNT_DEOBF_ACTION, TNT_DEOBF_CLI, TNT_DEOBF_ARGS, TNT_DEOBF_MODE, "
        "TNT_DEOBF_ARCH, TNT_DEOBF_DYNAMIC_ARGS, TNT_DEOBF_FORCE_REPROCESS, "
        "TNT_DEOBF_FORCE_REPAIR, TNT_DEOBF_REPAIR_PROFILE, TNT_DEOBF_TIMEOUT_SEC, "
        "TNT_DEOBF_NO_*_PROMPT env vars "
        "to customize behavior."
    )
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    def init(self):
        detected = _ida_version_tuple()
        if detected < MIN_IDA_VERSION:
            _msg(
                "requires IDA "
                f"{_ida_version_text(MIN_IDA_VERSION)}+; detected {_ida_version_text(detected)}. skipping."
            )
            return idaapi.PLUGIN_SKIP
        _msg("loaded.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        input_path = _get_input_path()
        if not input_path:
            _warn("Input file path is unavailable in this IDA session.")
            return

        action = _prompt_action(_normalize_action(os.environ.get("TNT_DEOBF_ACTION")) or "repair")
        if action is None:
            _msg("cancelled.")
            return

        deobf_ok = True
        output_path: str | None = None
        if action in {"deobfuscate", "both"}:
            deobf_ok, output_path = _run_cli(input_path)
            if not deobf_ok and output_path is None:
                _msg("deobfuscation step cancelled.")
                return

        if action in {"repair", "both"}:
            stats = _run_repair(input_path)
            if stats.skipped:
                _msg("repair skipped: markers already present.")
            elif stats.bootstrap_ea is None:
                _msg("repair skipped: bootstrap not found.")
            else:
                _msg(
                    "repair summary: "
                    f"bootstrap=0x{stats.bootstrap_ea:x} "
                    f"profile={stats.profile} "
                    f"wrappers={stats.wrappers_seen} "
                    f"renamed={stats.wrappers_renamed} "
                    f"literals={stats.literals_resolved} "
                    f"comments={stats.comments_added} "
                    f"str_created={stats.strings_created} "
                    f"data_notes={stats.data_notes_added}"
                )
                _msg("repair updates current IDB only; file bytes on disk are unchanged.")

        if action == "both" and output_path:
            try:
                same_file = os.path.samefile(input_path, output_path)
            except Exception:
                same_file = os.path.abspath(input_path) == os.path.abspath(output_path)
            if not same_file:
                _msg(
                    "note: repair was applied to the current IDB. "
                    "To repair the generated output file, load it in IDA and run plugin with action=repair."
                )

        if action in {"deobfuscate", "both"} and not deobf_ok:
            _msg("deobfuscation step failed.")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return TntDeobfuscatorPlugin()
