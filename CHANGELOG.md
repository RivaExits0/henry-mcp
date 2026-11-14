# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-14

### Added
- Initial release of henry-mcp MCP server for static compatibility analysis
- 5 MCP tools: `henry_inspect_file`, `henry_analyze_pair`, `henry_predict_failure_scenarios`, `henry_explain_finding`, `henry_reset`
- Support for Windows PE (EXE/DLL), Android APK, and Kotlin source files
- Compatibility analysis for EXE+DLL, APK+Kotlin, and APK+PE pairs
- Architecture matching, dependency detection, export validation
- Evidence-backed failure scenario prediction with severity/confidence
- Finding explanation with observed vs inferred values
- Pagination support for all analysis tools
- Cross-platform support (Windows/Linux) via `platform_utils.py`
- Comprehensive test suite (25 tests passing)
- CI pipeline (GitHub Actions: ubuntu-latest + windows-latest, Python 3.10/3.11/3.12)

### Security
- Read-only analysis (no execution, injection, or modification)
- Path traversal protection
- Size limits and parse timeouts
- No network access or filesystem scanning beyond user-provided paths

[0.1.0]: https://github.com/RivaExits0/henry-mcp/releases/tag/v0.1.0