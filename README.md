# henry-mcp

[![CI](https://github.com/RivaExits0/henry-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/RivaExits0/henry-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

**henry-mcp** is an MCP server for static compatibility analysis of
application/module pairs (EXE+DLL, APK+Kotlin, APK+native library). It
inspects file structure, imports/exports, permissions, and package information
to produce evidence-backed compatibility inferences — without executing,
injecting, or modifying any file.

## Supported file types

| Format | Extension | What is extracted |
|--------|-----------|-------------------|
| Windows PE (EXE) | `.exe` | Architecture, imports, exports, dependencies, sections |
| Windows PE (DLL) | `.dll` | Architecture, imports, exports, dependencies, sections |
| Android APK | `.apk` | Package, min/target/max SDK, permissions, native libs, DEX, components |
| Kotlin source | `.kt` | Package, imports, classes, functions, integration hints |

## Supported analysis pairs

| Pair | Description |
|------|-------------|
| EXE + DLL | Windows PE compatibility |
| APK + Kotlin | Android app + source compatibility |
| APK + PE | Android app + native library (PE) — flagged as incompatible (Android needs ELF .so) |

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

The server speaks MCP over stdio.

## OpenCode integration

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

## MCP tools

| Tool | Description |
|------|-------------|
| `henry_inspect_file(path)` | Inspect one file: type, format, architecture, imports/exports, package, permissions. |
| `henry_analyze_pair(app_path, module_path)` | Compare app + module: format, architecture, dependencies, integration conditions. |
| `henry_predict_failure_scenarios(app_path, module_path)` | Evidence-backed failure scenarios with severity, confidence, validation_needed. |
| `henry_explain_finding(finding_id)` | Explain a previous finding: observed vs inferred value, evidence. |
| `henry_reset()` | Clear all stored analysis findings and reports. |

## Testing

```bash
pip install pytest
python -m pytest -q
```

Tests use generated fixtures (no user-owned EXE/APK required).

## Static analysis vs runtime verification

- **Static analysis** (this tool): inspects file structure only. Cannot guarantee
  runtime behaviour, loading, or invocation.
- **Runtime verification**: required to confirm that a module actually loads
  and functions correctly in the target application.

## Security

- No `shell=True`; all subprocess use is avoided in the first release.
- No dump execution, injection, patching, re-signing, or file modification.
- No network access or filesystem scanning beyond user-provided paths.
- Size limits and parse timeouts protect against oversized/malformed files.
- Path traversal is rejected.
- Sensitive content (keys, tokens, passwords) is not dumped; only its
  presence is noted.

## Limitations

- PE analysis requires the `pefile` library.
- APK manifest parsing handles plain XML; binary-compiled manifests use a
  regex fallback with reduced accuracy.
- Kotlin parsing is regex-based; it does not perform full type resolution.
- No actual DLL loading, JNI binding, or classpath resolution is tested.
- Compatibility is an inference, not a guarantee.
- Findings are stored in-memory only; `henry_reset()` clears them.

## License

MIT — see [LICENSE](LICENSE).
