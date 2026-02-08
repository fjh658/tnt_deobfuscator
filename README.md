# TNT Mach-O Deobfuscator (Python) 🛠️

🌐 Language: **English** | [中文](README.zh-CN.md)

A static + dynamic deobfuscation tool for Mach-O binaries.

## ✨ Features

- ✅ Supports `x86_64` and `arm64`
- ✅ Supports thin Mach-O 64-bit
- ✅ Supports fat Mach-O (with architecture filtering)
- ✅ Static XOR range deobfuscation with boundary checks
- ✅ Dynamic Unicorn-based emulation + memory dump
- ✅ Symbol string restoration (`lazy bind + symtab`)
- ✅ Common section/segment name repair

## 🚀 Installation

Install from GitHub ZIP:

```bash
pip install https://github.com/fjh658/tnt_deobfuscator/archive/refs/heads/main.zip
```

Or local editable install:

```bash
pip install -e .
```

During install, the IDA plugin is deployed automatically:

- macOS / Linux: `~/.idapro/plugins/tnt_deobfuscator_ida.py`
- Windows: `%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\tnt_deobfuscator_ida.py`

## 🧪 CLI Usage

```bash
tnt-deobfuscator -i <input_binary> -o <output_binary>
```

Underscore alias is also available:

```bash
tnt_deobfuscator -i <input_binary> -o <output_binary>
```

Examples:

```bash
tnt-deobfuscator -i <input_binary> -o <output_binary> --arch all
tnt-deobfuscator -i <input_binary> -o <output_binary> --arch x86_64
tnt-deobfuscator -i <input_binary> -o <output_binary> --arch arm64
tnt-deobfuscator -i <input_binary> -o <output_binary> --mode static
tnt-deobfuscator -i <input_binary> -o <output_binary> --mode dynamic
tnt-deobfuscator -i <input_binary> -o <output_binary> --mode dynamic --emu-timeout-ms 30000 --emu-max-insn 2000000
tnt-deobfuscator -i <input_binary> --verbose
```

If `-o` is omitted, output defaults to `<input>.deobf`.

## 🧩 IDA Plugin Environment Variables

- `TNT_IDA_PLUGIN_DIR`: force plugin install directory (custom/testing)
- `TNT_DEOBF_SKIP_IDA_PLUGIN_INSTALL=1`: skip plugin auto-install
- `TNT_DEOBF_MODE`: default plugin mode (`static` / `dynamic`)
- `TNT_DEOBF_ARCH`: default plugin arch (`all` / `x86_64` / `arm64`)
- `TNT_DEOBF_DYNAMIC_ARGS`: dynamic-mode extra args (e.g. `--emu-timeout-ms 30000 --emu-max-insn 2000000`)
- `TNT_DEOBF_NO_MODE_PROMPT=1`: skip mode prompt and use `TNT_DEOBF_MODE`
- `TNT_DEOBF_NO_ARCH_PROMPT=1`: skip arch prompt and use `TNT_DEOBF_ARCH` (or IDA processor auto-detection)
- `TNT_DEOBF_NO_DYNAMIC_PROMPT=1`: skip dynamic args prompt
- `TNT_DEOBF_CLI`: override CLI command/path used by the plugin
- `TNT_DEOBF_ARGS`: append global extra CLI args

## 📝 Notes

- The tool scans obfuscation metadata after `mach_header_64 + sizeofcmds`.
- Each `(start, size)` chunk is XOR-restored using a computed key.
- Symbol restoration uses a safe replacement policy to avoid overwriting adjacent string slots.
- Dynamic mode requires Unicorn: `pip install unicorn`.

## 📄 License

Licensed under the MIT License. See `LICENSE`.
