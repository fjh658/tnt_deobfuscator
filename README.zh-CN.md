# TNT Mach-O 反混淆工具 (Python) 🛠️

🌐 语言: [English](README.md) | **中文**

一个面向 Mach-O 的静态 + 动态反混淆工具。

## ✨ 功能特性

- ✅ 支持 `x86_64` 和 `arm64`
- ✅ 支持 thin Mach-O 64-bit
- ✅ 支持 fat Mach-O（可按架构过滤）
- ✅ 支持静态 XOR 区段反混淆，并带边界检查
- ✅ 支持基于 Unicorn 的动态执行 + 内存转储
- ✅ 支持符号字符串恢复（`lazy bind + symtab`）
- ✅ 支持常见 section/segment 名称修复

## 🚀 安装

通过 GitHub ZIP 安装：

```bash
pip install https://github.com/fjh658/tnt_deobfuscator/archive/refs/heads/main.zip
```

或本地可编辑安装：

```bash
pip install -e .
```

安装时会自动部署 IDA 插件：

- macOS / Linux: `~/.idapro/plugins/tnt_deobfuscator_ida.py`
- Windows: `%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\tnt_deobfuscator_ida.py`

## 🧪 命令行用法

```bash
tnt-deobfuscator -i <input_binary> -o <output_binary>
```

也支持下划线命令别名：

```bash
tnt_deobfuscator -i <input_binary> -o <output_binary>
```

示例：

```bash
tnt-deobfuscator -i <input_binary> -o <output_binary> --arch all
tnt-deobfuscator -i <input_binary> -o <output_binary> --arch x86_64
tnt-deobfuscator -i <input_binary> -o <output_binary> --arch arm64
tnt-deobfuscator -i <input_binary> -o <output_binary> --mode static
tnt-deobfuscator -i <input_binary> -o <output_binary> --mode dynamic
tnt-deobfuscator -i <input_binary> -o <output_binary> --mode dynamic --emu-timeout-ms 30000 --emu-max-insn 2000000
tnt-deobfuscator -i <input_binary> --verbose
```

如果不传 `-o`，默认输出为 `<input>.deobf`。

## 🧩 IDA 插件环境变量

- `TNT_IDA_PLUGIN_DIR`: 强制插件安装目录（自定义/测试）
- `TNT_DEOBF_SKIP_IDA_PLUGIN_INSTALL=1`: 跳过插件自动安装
- `TNT_DEOBF_MODE`: 插件默认模式（`static` / `dynamic`）
- `TNT_DEOBF_ARCH`: 插件默认架构（`all` / `x86_64` / `arm64`）
- `TNT_DEOBF_DYNAMIC_ARGS`: 动态模式附加参数（例如 `--emu-timeout-ms 30000 --emu-max-insn 2000000`）
- `TNT_DEOBF_NO_MODE_PROMPT=1`: 不弹出模式选择，直接使用 `TNT_DEOBF_MODE`
- `TNT_DEOBF_NO_ARCH_PROMPT=1`: 不弹出架构选择，直接使用 `TNT_DEOBF_ARCH`（或按 IDA 处理器自动判断）
- `TNT_DEOBF_NO_DYNAMIC_PROMPT=1`: 动态模式不弹附加参数输入框
- `TNT_DEOBF_CLI`: 覆盖插件调用的 CLI 命令/路径
- `TNT_DEOBF_ARGS`: 追加全局 CLI 参数

## 📝 说明

- 工具会在 `mach_header_64 + sizeofcmds` 之后扫描混淆元数据。
- 每个 `(start, size)` 区段会按计算出的 XOR key 执行恢复。
- 符号恢复采用安全替换策略，避免覆盖相邻字符串槽位。
- 动态模式依赖 Unicorn：`pip install unicorn`。

## 📄 许可证

本项目采用 MIT License，见 `LICENSE`。
