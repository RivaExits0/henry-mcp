"""henry-mcp: Static compatibility analysis MCP server.

Provides read-only static analysis of EXE/DLL/APK/Kotlin files to assess
compatibility between an application and a module. No files are executed,
injected, or modified.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    from mcp.server.mcpserver import MCPServer as FastMCP

from analyzer import Analyzer

mcp = FastMCP("henry")
analyzer = Analyzer()


def _to_json(obj: Any) -> str:
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, ensure_ascii=False, default=str)


def _validate_path(path: str) -> str:
    """Basic path validation: must exist and be a file."""
    if not path or not isinstance(path, str):
        raise ValueError("path must be a non-empty string")
    # Normalize and reject path traversal attempts
    norm = os.path.normpath(path)
    if norm.startswith("..") or ".." in norm.split(os.sep):
        raise ValueError(f"unsafe path (traversal): {path}")
    if not os.path.isfile(norm):
        raise ValueError(f"file not found: {path}")
    return norm


@mcp.tool()
def henry_inspect_file(path: str, limit: int = 1000, offset: int = 0) -> str:
    """Inspect a single file statically and return a structured report.

    Use this first to understand a file's type, format, and key properties
    before comparing it with another file.

    Supported formats:
      - Windows PE (EXE / DLL): architecture, imports, exports, dependencies
      - Android APK: package, SDK, permissions, native libraries, DEX files
      - Kotlin source (.kt): package, imports, classes, functions

    Args:
        path: Absolute or relative path to the file to inspect.
        limit: Maximum number of findings to return (default 1000).
        offset: Number of findings to skip (default 0).
    """
    try:
        _validate_path(path)
        result = analyzer.inspect_file(path, limit=limit, offset=offset)
        return _to_json(result)
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def henry_analyze_pair(app_path: str, module_path: str,
                       limit: int = 1000, offset: int = 0) -> str:
    """Compare an application file with a module file for static compatibility.

    Supported pairs:
      - EXE + DLL (Windows PE)
      - APK + Kotlin source (.kt)
      - APK + native library (PE)

    The result is an evidence-backed inference, not a runtime guarantee.
    No files are loaded or executed.

    Args:
        app_path: Path to the application file (EXE or APK).
        module_path: Path to the module file (DLL or Kotlin source).
        limit: Maximum number of findings to return (default 1000).
        offset: Number of findings to skip (default 0).
    """
    try:
        _validate_path(app_path)
        _validate_path(module_path)
        result = analyzer.analyze_pair(app_path, module_path, limit=limit, offset=offset)
        return _to_json(result)
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def henry_predict_failure_scenarios(app_path: str, module_path: str,
                                    limit: int = 1000, offset: int = 0) -> str:
    """Predict likely failure scenarios for an app + module pair.

    Each scenario includes title, condition, symptom, cause, evidence,
    severity, confidence, and validation_needed. Only scenarios supported
    by static findings are produced.

    Args:
        app_path: Path to the application file.
        module_path: Path to the module file.
        limit: Maximum number of scenarios to return (default 1000).
        offset: Number of scenarios to skip (default 0).
    """
    try:
        _validate_path(app_path)
        _validate_path(module_path)
        result = analyzer.predict_failure_scenarios(app_path, module_path,
                                                    limit=limit, offset=offset)
        return _to_json(result)
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def henry_explain_finding(finding_id: str) -> str:
    """Explain a previously produced finding by its ID.

    Use after henry_inspect_file, henry_analyze_pair, or
    henry_predict_failure_scenarios to understand why a particular
    observation or inference was reported.

    Args:
        finding_id: The ID of the finding to explain.
    """
    try:
        if not finding_id or not isinstance(finding_id, str):
            return "error: finding_id must be a non-empty string"
        result = analyzer.explain_finding(finding_id)
        return _to_json(result)
    except Exception as exc:
        return f"error: {exc}"


@mcp.tool()
def henry_reset() -> str:
    """Clear all stored analysis findings and reports.

    Use this to reset the analyzer's in-memory state between
    unrelated analysis sessions.
    """
    try:
        result = analyzer.reset()
        return _to_json(result)
    except Exception as exc:
        return f"error: {exc}"


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
