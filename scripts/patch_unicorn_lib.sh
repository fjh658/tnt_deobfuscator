#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
CMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
PY_UNICORN_LIB="${PY_UNICORN_LIB:-}"
BREW_UNICORN_LIB="${BREW_UNICORN_LIB:-}"
UNICORN_SRC="${UNICORN_SRC:-}"
UNICORN_BUILD_DIR="${UNICORN_BUILD_DIR:-}"
PATCH_BREW=1
CLEAN_BUILD=0
GIT_PULL=1
GIT_REMOTE="${GIT_REMOTE:-origin}"
GIT_BRANCH="${GIT_BRANCH:-}"
ALLOW_DIRTY=0
CLONE_URL="${CLONE_URL:-git@github.com:fjh658/unicorn.git}"
CLONE_DIR="${CLONE_DIR:-$PWD/unicorn}"
AUTO_CLONE=1
REQUIRED_UC_SYMBOLS=(uc_version uc_open uc_close uc_mem_map uc_mem_read uc_mem_write uc_emu_start)
FORCE_REPLACE=0

usage() {
  cat <<'EOF'
Usage: patch_unicorn_lib.sh [--clean] [--python-only|--brew-only]

Quick start (no extra args needed):
  1) Auto-detect local unicorn source;
  2) If not found, auto-clone from:
     git@github.com:fjh658/unicorn.git
     into: ./unicorn
  3) git pull --ff-only;
  4) build libunicorn.2.dylib;
  5) replace Python + Homebrew unicorn dylib and create backups.

Common options:
  --clean            Remove build directory before building.
  --python-only      Patch Python unicorn library only.
  --brew-only        Patch Homebrew unicorn library only.
  --force-replace    Replace even when target hash equals built hash.
  --help             Show this help.

Advanced options:
  --source <dir>     Use an existing unicorn source directory.
  --build-dir <dir>  Set custom CMake build directory.
  --clone-url <url>  Override clone URL.
  --clone-dir <dir>  Override clone directory (default: ./unicorn).
  --no-auto-clone    Disable auto-clone fallback.
  --no-git-pull      Skip git sync before build.
  --remote <name>    Git remote name (default: origin).
  --branch <name>    Git branch to pull.
  --allow-dirty      Allow running with local uncommitted changes.
EOF
}

is_unicorn_src() {
  local src="$1"
  [[ -d "$src" ]] || return 1
  [[ -f "$src/CMakeLists.txt" ]] || return 1
  [[ -f "$src/include/unicorn/unicorn.h" ]] || return 1
}

detect_unicorn_src() {
  local candidate="$PWD/unicorn"
  if is_unicorn_src "$candidate"; then
    echo "$candidate"
    return 0
  fi
  return 1
}

resolve_unicorn_src() {
  if [[ -n "$UNICORN_SRC" ]]; then
    echo "$UNICORN_SRC"
    return 0
  fi
  if detect_unicorn_src; then
    return 0
  fi
  if [[ "$AUTO_CLONE" -eq 0 ]]; then
    return 1
  fi
  clone_unicorn_src
}

resolve_build_dir() {
  local src="$1"
  if [[ -n "$UNICORN_BUILD_DIR" ]]; then
    echo "$UNICORN_BUILD_DIR"
    return 0
  fi
  echo "$src/build-agent-patched"
}

clone_unicorn_src() {
  if ! command -v git >/dev/null 2>&1; then
    echo "[ERROR] git is required for auto-clone fallback." >&2
    return 1
  fi

  local clone_dir="$CLONE_DIR"
  echo "[INFO] source not found locally; cloning unicorn repo" >&2
  echo "[INFO] clone url: $CLONE_URL" >&2
  echo "[INFO] clone dir: $clone_dir" >&2

  if [[ -e "$clone_dir" ]]; then
    if is_unicorn_src "$clone_dir"; then
      echo "[INFO] clone dir already contains a unicorn source tree, reuse: $clone_dir" >&2
      echo "$clone_dir"
      return 0
    fi
    echo "[ERROR] clone target exists but is not a valid unicorn source: $clone_dir" >&2
    echo "        use --source <dir> or --clone-dir <empty_dir>." >&2
    return 1
  fi

  mkdir -p "$(dirname "$clone_dir")"
  if [[ -n "$GIT_BRANCH" ]]; then
    git clone --branch "$GIT_BRANCH" "$CLONE_URL" "$clone_dir"
  else
    git clone "$CLONE_URL" "$clone_dir"
  fi

  if ! is_unicorn_src "$clone_dir"; then
    echo "[ERROR] cloned directory is not a valid unicorn source: $clone_dir" >&2
    return 1
  fi

  echo "$clone_dir"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source|-s)
      [[ $# -ge 2 ]] || { echo "[ERROR] --source requires a value" >&2; exit 1; }
      UNICORN_SRC="$2"
      shift
      ;;
    --build-dir|-B)
      [[ $# -ge 2 ]] || { echo "[ERROR] --build-dir requires a value" >&2; exit 1; }
      UNICORN_BUILD_DIR="$2"
      shift
      ;;
    --clean)
      CLEAN_BUILD=1
      ;;
    --python-only)
      PATCH_BREW=0
      ;;
    --brew-only)
      PY_UNICORN_LIB="__SKIP__"
      ;;
    --clone-url)
      [[ $# -ge 2 ]] || { echo "[ERROR] --clone-url requires a value" >&2; exit 1; }
      CLONE_URL="$2"
      shift
      ;;
    --clone-dir)
      [[ $# -ge 2 ]] || { echo "[ERROR] --clone-dir requires a value" >&2; exit 1; }
      CLONE_DIR="$2"
      shift
      ;;
    --no-auto-clone)
      AUTO_CLONE=0
      ;;
    --no-git-pull)
      GIT_PULL=0
      ;;
    --remote)
      [[ $# -ge 2 ]] || { echo "[ERROR] --remote requires a value" >&2; exit 1; }
      GIT_REMOTE="$2"
      shift
      ;;
    --branch)
      [[ $# -ge 2 ]] || { echo "[ERROR] --branch requires a value" >&2; exit 1; }
      GIT_BRANCH="$2"
      shift
      ;;
    --allow-dirty)
      ALLOW_DIRTY=1
      ;;
    --force-replace)
      FORCE_REPLACE=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if ! UNICORN_SRC="$(resolve_unicorn_src)"; then
  echo "[ERROR] unable to auto-detect unicorn source directory." >&2
  echo "        use --source <dir> or set UNICORN_SRC." >&2
  exit 1
fi

if ! is_unicorn_src "$UNICORN_SRC"; then
  echo "[ERROR] invalid unicorn source directory: $UNICORN_SRC" >&2
  exit 1
fi

UNICORN_BUILD_DIR="$(resolve_build_dir "$UNICORN_SRC")"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] python executable not found: $PYTHON_BIN" >&2
  exit 1
fi

detect_python_unicorn_lib() {
  "$PYTHON_BIN" - <<'PY'
import pathlib
import unicorn

path = pathlib.Path(unicorn.__file__).resolve().parent / "lib" / "libunicorn.2.dylib"
print(path)
PY
}

detect_brew_unicorn_lib() {
  if [[ -n "$BREW_UNICORN_LIB" ]]; then
    echo "$BREW_UNICORN_LIB"
    return 0
  fi

  if command -v brew >/dev/null 2>&1; then
    local prefix
    prefix="$(brew --prefix unicorn 2>/dev/null || true)"
    if [[ -n "$prefix" ]]; then
      local candidate="$prefix/lib/libunicorn.2.dylib"
      if [[ -f "$candidate" ]]; then
        echo "$candidate"
        return 0
      fi
    fi
  fi

  for candidate in \
    /opt/homebrew/opt/unicorn/lib/libunicorn.2.dylib \
    /usr/local/opt/unicorn/lib/libunicorn.2.dylib
  do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
}

add_target() {
  local candidate="$1"
  if [[ -z "$candidate" ]]; then
    return
  fi
  local item
  for item in "${TARGETS[@]:-}"; do
    if [[ "$item" == "$candidate" ]]; then
      return
    fi
  done
  TARGETS+=("$candidate")
}

archs_of_macho() {
  local path="$1"
  if ! command -v lipo >/dev/null 2>&1; then
    return 1
  fi
  lipo -archs "$path" 2>/dev/null || return 1
}

contains_word() {
  local haystack="$1"
  local needle="$2"
  [[ " $haystack " == *" $needle "* ]]
}

sha256_of_file() {
  local path="$1"
  shasum -a 256 "$path" | awk '{print $1}'
}

dylib_major_from_string() {
  local value="$1"
  if [[ "$value" =~ \.([0-9]+)\.dylib$ ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

dylib_id_name() {
  local path="$1"
  if ! command -v otool >/dev/null 2>&1; then
    return 1
  fi
  otool -D "$path" 2>/dev/null | sed -n '2p'
}

dylib_compat_major() {
  local path="$1"
  if ! command -v otool >/dev/null 2>&1; then
    return 1
  fi
  otool -L "$path" 2>/dev/null | sed -n '2s/.*compatibility version \([0-9][0-9]*\).*/\1/p'
}

extract_uc_exports() {
  local path="$1"
  if ! command -v nm >/dev/null 2>&1; then
    return 1
  fi
  nm -gU "$path" 2>/dev/null | awk '{gsub(/^_/, "", $3); if ($3 ~ /^uc_/) print $3}' | sort -u || true
}

validate_target_replace() {
  local built="$1"
  local target="$2"

  if [[ ! -f "$target" ]]; then
    echo "[WARN] target library not found, skip: $target"
    return 1
  fi

  if [[ ! -w "$target" && ! -w "$(dirname "$target")" ]]; then
    echo "[ERROR] target is not writable: $target" >&2
    return 2
  fi

  local built_file target_file
  built_file="$(file -b "$built" 2>/dev/null || true)"
  target_file="$(file -b "$target" 2>/dev/null || true)"
  if [[ "$built_file" != *"Mach-O"* ]]; then
    echo "[ERROR] built library is not Mach-O: $built ($built_file)" >&2
    return 2
  fi
  if [[ "$target_file" != *"Mach-O"* ]]; then
    echo "[ERROR] target library is not Mach-O: $target ($target_file)" >&2
    return 2
  fi

  local built_archs target_archs
  built_archs="$(archs_of_macho "$built" || true)"
  target_archs="$(archs_of_macho "$target" || true)"
  if [[ -n "$built_archs" && -n "$target_archs" ]]; then
    local arch
    for arch in $target_archs; do
      if ! contains_word "$built_archs" "$arch"; then
        echo "[ERROR] arch mismatch: target requires '$arch' but built has '$built_archs' ($target)" >&2
        return 2
      fi
    done
  else
    echo "[WARN] unable to verify Mach-O archs via lipo for target: $target"
  fi

  local built_name_major target_name_major
  built_name_major="$(dylib_major_from_string "$(basename "$built")" || true)"
  target_name_major="$(dylib_major_from_string "$(basename "$target")" || true)"
  if [[ -n "$built_name_major" && -n "$target_name_major" && "$built_name_major" != "$target_name_major" ]]; then
    echo "[ERROR] dylib major mismatch by filename: built=$built_name_major target=$target_name_major ($target)" >&2
    return 2
  fi

  local built_id target_id built_id_major target_id_major
  built_id="$(dylib_id_name "$built" || true)"
  target_id="$(dylib_id_name "$target" || true)"
  built_id_major="$(dylib_major_from_string "$built_id" || true)"
  target_id_major="$(dylib_major_from_string "$target_id" || true)"
  if [[ -n "$built_id_major" && -n "$target_id_major" && "$built_id_major" != "$target_id_major" ]]; then
    echo "[ERROR] dylib major mismatch by install-name: built=$built_id target=$target_id ($target)" >&2
    return 2
  fi

  local built_compat_major target_compat_major
  built_compat_major="$(dylib_compat_major "$built" || true)"
  target_compat_major="$(dylib_compat_major "$target" || true)"
  if [[ -n "$built_compat_major" && -n "$target_compat_major" && "$built_compat_major" != "$target_compat_major" ]]; then
    echo "[ERROR] compatibility version major mismatch: built=$built_compat_major target=$target_compat_major ($target)" >&2
    return 2
  fi

  if command -v nm >/dev/null 2>&1 && command -v comm >/dev/null 2>&1; then
    local built_sym_file target_sym_file missing_syms
    built_sym_file="$(mktemp "${TMPDIR:-/tmp}/unicorn-built-syms.XXXXXX")"
    target_sym_file="$(mktemp "${TMPDIR:-/tmp}/unicorn-target-syms.XXXXXX")"
    extract_uc_exports "$built" >"$built_sym_file"
    extract_uc_exports "$target" >"$target_sym_file"

    if [[ ! -s "$built_sym_file" ]]; then
      echo "[ERROR] unable to extract uc_* exports from built library: $built" >&2
      rm -f "$built_sym_file" "$target_sym_file"
      return 2
    fi

    local req
    for req in "${REQUIRED_UC_SYMBOLS[@]}"; do
      if ! grep -Fxq "$req" "$built_sym_file"; then
        echo "[ERROR] built library missing required symbol '$req': $built" >&2
        rm -f "$built_sym_file" "$target_sym_file"
        return 2
      fi
    done

    if [[ -s "$target_sym_file" ]]; then
      missing_syms="$(comm -23 "$target_sym_file" "$built_sym_file" || true)"
      if [[ -n "$missing_syms" ]]; then
        echo "[ERROR] built library misses exported uc_* symbols required by target: $target" >&2
        echo "$missing_syms" | sed 's/^/        - /' >&2
        rm -f "$built_sym_file" "$target_sym_file"
        return 2
      fi
    else
      echo "[WARN] unable to extract uc_* exports from target; skip symbol subset check: $target"
    fi
    rm -f "$built_sym_file" "$target_sym_file"
  else
    echo "[WARN] nm/comm unavailable; skip symbol compatibility check for target: $target"
  fi

  return 0
}

preflight_targets() {
  VALID_TARGETS=()
  local target
  for target in "${TARGETS[@]}"; do
    if validate_target_replace "$BUILT_LIB" "$target"; then
      VALID_TARGETS+=("$target")
    else
      local rc=$?
      if [[ "$rc" -eq 2 ]]; then
        exit 1
      fi
    fi
  done
  if [[ "${#VALID_TARGETS[@]}" -eq 0 ]]; then
    echo "[ERROR] no valid target unicorn library for replacement." >&2
    exit 1
  fi
}

sync_unicorn_repo() {
  if [[ "$GIT_PULL" -eq 0 ]]; then
    echo "[INFO] git sync disabled (--no-git-pull)"
    return 0
  fi

  if ! command -v git >/dev/null 2>&1; then
    echo "[WARN] git not found, skip source sync"
    return 0
  fi

  if [[ ! -d "$UNICORN_SRC/.git" ]]; then
    echo "[WARN] source is not a git repo, skip source sync: $UNICORN_SRC"
    return 0
  fi

  if [[ "$ALLOW_DIRTY" -ne 1 ]]; then
    local dirty
    dirty="$(git -C "$UNICORN_SRC" status --porcelain --untracked-files=no)"
    if [[ -n "$dirty" ]]; then
      echo "[ERROR] git repo has uncommitted changes: $UNICORN_SRC" >&2
      echo "        commit/stash first, or use --allow-dirty to continue." >&2
      exit 1
    fi
  fi

  local branch
  branch="$GIT_BRANCH"
  if [[ -z "$branch" ]]; then
    branch="$(git -C "$UNICORN_SRC" rev-parse --abbrev-ref HEAD)"
  fi
  if [[ "$branch" == "HEAD" || -z "$branch" ]]; then
    echo "[ERROR] detached HEAD; specify --branch <name> for git pull." >&2
    exit 1
  fi

  echo "[INFO] syncing source via git pull: remote=$GIT_REMOTE branch=$branch"
  if git -C "$UNICORN_SRC" rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1 && [[ -z "$GIT_BRANCH" ]]; then
    git -C "$UNICORN_SRC" pull --ff-only
  else
    git -C "$UNICORN_SRC" pull --ff-only "$GIT_REMOTE" "$branch"
  fi
}

echo "[INFO] unicorn source: $UNICORN_SRC"
echo "[INFO] unicorn build dir: $UNICORN_BUILD_DIR"
echo "[INFO] python bin: $PYTHON_BIN"
echo "[INFO] auto clone: $AUTO_CLONE url=$CLONE_URL dir=$CLONE_DIR"
echo "[INFO] git pull: $GIT_PULL remote=$GIT_REMOTE branch=${GIT_BRANCH:-<auto>}"
echo "[INFO] force replace: $FORCE_REPLACE"

if [[ "$CLEAN_BUILD" -eq 1 ]]; then
  echo "[INFO] cleaning build dir: $UNICORN_BUILD_DIR"
  rm -rf "$UNICORN_BUILD_DIR"
fi

sync_unicorn_repo

cmake -S "$UNICORN_SRC" -B "$UNICORN_BUILD_DIR" -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE"
cmake --build "$UNICORN_BUILD_DIR" -j"$(sysctl -n hw.ncpu 2>/dev/null || echo 8)" --target unicorn

BUILT_LIB="$UNICORN_BUILD_DIR/libunicorn.2.dylib"
if [[ ! -f "$BUILT_LIB" ]]; then
  echo "[ERROR] built library not found: $BUILT_LIB" >&2
  exit 1
fi

echo "[INFO] built library: $BUILT_LIB"
shasum -a 256 "$BUILT_LIB"

TARGETS=()
if [[ "$PY_UNICORN_LIB" == "__SKIP__" ]]; then
  :
elif [[ -n "$PY_UNICORN_LIB" ]]; then
  add_target "$PY_UNICORN_LIB"
else
  add_target "$(detect_python_unicorn_lib)"
fi
if [[ "$PATCH_BREW" -eq 1 ]]; then
  add_target "$(detect_brew_unicorn_lib || true)"
fi

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  echo "[ERROR] no target unicorn library discovered." >&2
  exit 1
fi

preflight_targets

echo "[INFO] target libraries:"
for target in "${VALID_TARGETS[@]}"; do
  echo "  - $target"
done

timestamp="$(date +%Y%m%d_%H%M%S)"
patched_count=0
skipped_count=0
built_hash=""
if [[ "$FORCE_REPLACE" -eq 0 ]]; then
  built_hash="$(sha256_of_file "$BUILT_LIB")"
fi
for target in "${VALID_TARGETS[@]}"; do
  if [[ "$FORCE_REPLACE" -eq 0 ]]; then
    target_hash="$(sha256_of_file "$target")"
    if [[ "$built_hash" == "$target_hash" ]]; then
      echo "[SKIP] identical hash, already up to date: $target"
      skipped_count=$((skipped_count + 1))
      continue
    fi
  fi
  backup="${target}.bak.${timestamp}"
  cp -f "$target" "$backup"
  cp -f "$BUILT_LIB" "$target"
  echo "[OK] patched: $target"
  echo "[OK] backup : $backup"
  patched_count=$((patched_count + 1))
done
echo "[INFO] replace summary: patched=$patched_count skipped=$skipped_count"

TARGETS_ENV="$(printf '%s\n' "${TARGETS[@]}")"
TARGETS_ENV="$TARGETS_ENV" "$PYTHON_BIN" - <<'PY'
import os
from pathlib import Path

paths = [Path(x.strip()) for x in os.environ.get("TARGETS_ENV", "").splitlines() if x.strip()]

def ctr_el0_mrs_count(data: bytes) -> int:
    count = 0
    for i in range(len(data) - 3):
        word = int.from_bytes(data[i : i + 4], "little")
        if (word & 0xFFFFFFE0) == 0xD53B0020:
            count += 1
    return count

for p in paths:
    if not p.exists():
        print(f"[WARN] not found: {p}")
        continue
    data = p.read_bytes()
    print(f"[CHECK] {p} size={p.stat().st_size} ctr_el0_mrs={ctr_el0_mrs_count(data)}")
PY

"$PYTHON_BIN" -u - <<'PY'
import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64

print("[CHECK] unicorn module:", unicorn.__file__, flush=True)
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(0x1000000, 0x1000)
print("[CHECK] uc_open + mem_map: OK", flush=True)
PY

echo "[DONE] unicorn library refresh complete."
