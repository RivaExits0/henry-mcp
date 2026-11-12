# henry-mcp

[![CI](https://github.com/RivaExits0/henry-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/henry-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**henry-mcp** is an MCP server for **static compatibility analysis** of
application/module pairs (EXE+DLL, APK+Kotlin, APK+native library). It
inspects file structure, imports/exports, permissions, and package information
to produce **evidence-backed compatibility inferences** — without executing,
injecting, or modifying any file.

> **Turkish / Türkçe:** henry-mcp, EXE+DLL, APK+Kotlin ve APK+native
> kütüphane çiftlerinin statik uyumluluğunu analiz eden bir MCP sunucusudur.
> Dosya yapısı, import/export, izinler ve paket bilgilerini inceleyerek
> kanıtla desteklenen uyumluluk tahminleri üretir. Hiçbir dosyayı çalıştırmaz,
> enjekte etmez veya değiştirmez.

## Supported File Types

| Format | Extension | What is extracted |
|--------|-----------|-------------------|
| Windows PE (EXE) | `.exe` | Architecture, imports, exports, dependencies, sections |
| Windows PE (DLL) | `.dll` | Architecture, imports, exports, dependencies, sections |
| Android APK | `.apk` | Package, min/target/max SDK, permissions, native libs, DEX, components |
| Kotlin source | `.kt` | Package, imports, classes, functions, integration hints |

## Supported Analysis Pairs

| Pair | Description |
|------|-------------|
| EXE + DLL | Windows PE compatibility — same architecture check, missing dependency detection |
| APK + Kotlin | Android app + source compatibility — package match, Android API hints |
| APK + PE | Android app + native library (PE) — flagged as incompatible (Android needs ELF `.so`) |

## Install

```bash
pip install "mcp>=1.0" pefile
```

Or from source:

```bash
git clone https://github.com/RivaExits0/henry-mcp.git
cd henry-mcp
pip install -e .
```

## Run

```bash
python server.py
```

The server speaks MCP over **stdio**.

## OpenCode Integration

Add to `opencode.json`:

```json
{
  "mcp": {
    "henry": {
      "type": "local",
      "command": ["python", "/path/to/henry-mcp/server.py"],
      "enabled": true
    }
  }
}
```

## MCP Tools

| Tool | Description | When to call |
|------|-------------|--------------|
| `henry_inspect_file(path, limit, offset)` | Inspect one file: type, format, architecture, imports/exports, package, permissions. | First, before any other tool. |
| `henry_analyze_pair(app_path, module_path, limit, offset)` | Compare app + module: format, architecture, dependencies, integration conditions. | After inspecting both files individually. |
| `henry_predict_failure_scenarios(app_path, module_path, limit, offset)` | Evidence-backed failure scenarios with severity, confidence, validation_needed. | After `analyze_pair`, to see what could go wrong. |
| `henry_explain_finding(finding_id)` | Explain a previous finding: observed vs inferred value, evidence. | When you want details about a specific finding ID. |
| `henry_reset()` | Clear all stored analysis findings and reports. | Between unrelated analysis sessions. |

### Tool: `henry_inspect_file`

**Example call:**
```json
{"tool": "henry_inspect_file", "args": {"path": "/path/to/app.exe", "limit": 10, "offset": 0}}
```

**Example output (EXE):**
```json
{
  "summary": "Static inspection of app.exe (pe).",
  "format": "pe",
  "file": "/path/to/app.exe",
  "info": {
    "format": "pe",
    "file_type": "EXE",
    "architecture": "x64 (amd64)",
    "machine_hex": "0x8664",
    "is_dll": false,
    "entry_point": "0x00001000",
    "image_base": "0x140001000",
    "sections": [],
    "section_count": 0,
    "imports": [],
    "import_dll_count": 0,
    "dependencies": ["kernel32.dll", "user32.dll"],
    "dependency_count": 2,
    "exports": [],
    "export_count": 0
  },
  "findings": [...],
  "pagination": {
    "total": 5,
    "offset": 0,
    "limit": 10,
    "returned": 5,
    "has_more": false
  },
  "warnings": ["This is a static report only..."],
  "limitations": ["Static analysis cannot guarantee runtime behaviour..."]
}
```

**Example output (APK):**
```json
{
  "format": "apk",
  "info": {
    "format": "apk",
    "package_name": "com.example.testapp",
    "min_sdk": "21",
    "target_sdk": "34",
    "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
    "native_libraries": ["lib/arm64-v8a/libnative.so"],
    "dex_files": ["classes.dex"],
    "entry_points": [".MainActivity"]
  },
  ...
}
```

### Tool: `henry_analyze_pair`

**Example call:**
```json
{"tool": "henry_analyze_pair", "args": {"app_path": "/path/to/app.exe", "module_path": "/path/to/module.dll", "limit": 20, "offset": 0}}
```

**Example output:**
```json
{
  "format": "pair",
  "findings": [
    {
      "id": "a1b2c3d4e5f6",
      "field": "format_pair",
      "inferred_value": "Supported pair: EXE/DLL on Windows",
      "confidence": "high",
      "evidence": ["app=pe, module=pe"]
    },
    {
      "id": "f7e8d9c0b1a2",
      "field": "architecture_match",
      "inferred_value": "architectures match",
      "confidence": "high",
      "evidence": ["app machine: 0x8664", "module machine: 0x8664"]
    },
    {
      "id": "3h4i5j6k7l8m",
      "field": "integration_condition",
      "inferred_value": "Copying a module file next to the application does not cause it to be loaded...",
      "confidence": "high",
      "evidence": ["General Windows/Android loading semantics"]
    }
  ],
  "pagination": {...}
}
```

### Tool: `henry_predict_failure_scenarios`

**Example call:**
```json
{"tool": "henry_predict_failure_scenarios", "args": {"app_path": "/path/to/app.exe", "module_path": "/path/to/module.dll", "limit": 10, "offset": 0}}
```

**Example output:**
```json
{
  "scenarios": [
    {
      "title": "Architecture mismatch between EXE and DLL",
      "condition": "App is x86 (i386), module is x64 (amd64).",
      "symptom": "LoadLibrary fails with ERROR_BAD_EXE_FORMAT (0xC1) or the process crashes on load.",
      "cause": "Windows cannot load a DLL built for a different CPU architecture into a process.",
      "evidence": ["app architecture: x86 (i386)", "module architecture: x64 (amd64)"],
      "severity": "high",
      "confidence": "high",
      "validation_needed": "Rebuild the DLL for the same architecture as the EXE."
    },
    {
      "title": "DLL has no exported functions",
      "condition": "The DLL exports zero symbols.",
      "symptom": "GetProcAddress returns NULL for any function name; the module is not callable.",
      "cause": "No exported entry points means no way for the application to invoke DLL code.",
      "evidence": ["module export_count: 0"],
      "severity": "high",
      "confidence": "high",
      "validation_needed": "Add __declspec(dllexport) or a .def file to the DLL."
    }
  ],
  "pagination": {...}
}
```

### Tool: `henry_explain_finding`

**Example call:**
```json
{"tool": "henry_explain_finding", "args": {"finding_id": "a1b2c3d4e5f6"}}
```

**Example output:**
```json
{
  "finding_id": "a1b2c3d4e5f6",
  "type": "observation",
  "file": "/path/to/app.exe + /path/to/module.dll",
  "field": "architecture_match",
  "observed_value": {"app": "x64 (amd64)", "module": "x64 (amd64)"},
  "inferred_value": "architectures match",
  "confidence": "high",
  "evidence": ["app machine: 0x8664", "module machine: 0x8664"],
  "notes": null
}
```

### Tool: `henry_reset`

**Example call:**
```json
{"tool": "henry_reset", "args": {}}
```

**Example output:**
```json
{"cleared_findings": 12}
```

## Pagination (`limit` / `offset`)

All three analysis tools (`henry_inspect_file`, `henry_analyze_pair`, `henry_predict_failure_scenarios`) support `limit` and `offset` for long result lists:

- `limit`: maximum number of items to return (default 1000, max 1000)
- `offset`: number of items to skip (default 0)

Response includes a `pagination` object with `total`, `offset`, `limit`, `returned`, and `has_more`.

## Testing

```bash
pip install pytest
python -m pytest -q
```

Tests use generated fixtures (no user-owned EXE/APK required). 25 unit tests + 1 MCP smoke test.

## Static Analysis vs Runtime Verification

| | Static Analysis (this tool) | Runtime Verification |
|---|---|---|
| What it does | Inspects file structure only | Actually loads and invokes the module |
| Guarantees | None — inference only | Confirms real behaviour |
| Safety | Safe, read-only | May execute code |
| Use case | Quick compatibility check | Final validation before deployment |

**Important:** henry-mcp never executes, injects, patches, or modifies any file. All conclusions are static inferences, not runtime guarantees.

## Security

- No `shell=True`; all external commands use argument lists (none in first release).
- No dump execution, injection, patching, re-signing, or file modification.
- No network access or filesystem scanning beyond user-provided paths.
- Size limits and parse timeouts protect against oversized/malformed files.
- Path traversal is rejected.
- Sensitive content (keys, tokens, passwords) is not dumped; only its presence is noted.

## Limitations

- PE analysis requires the `pefile` library.
- APK manifest parsing handles plain XML; binary-compiled manifests use a regex fallback with reduced accuracy.
- Kotlin parsing is regex-based; it does not perform full type resolution.
- No actual DLL loading, JNI binding, or classpath resolution is tested.
- Compatibility is an inference, not a guarantee.
- Findings are stored in-memory only; `henry_reset()` clears them.

## License

MIT — see [LICENSE](LICENSE).
