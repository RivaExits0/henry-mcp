"""File type detection and static info extraction for henry-mcp.

Supports:
  - Windows PE (EXE / DLL)
  - Android APK (ZIP + AndroidManifest.xml)
  - Kotlin source (.kt)

All extraction is read-only and static. No files are executed or modified.
"""

from __future__ import annotations

import os
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

# Magic byte signatures
MAGIC_PE = b"MZ"
MAGIC_APK_ZIP = b"PK\x03\x04"

# Size limits (bytes) to protect against oversized/malformed files
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
MAX_ZIP_ENTRIES = 50000
MAX_APK_MANIFEST_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_KOTLIN_SIZE = 5 * 1024 * 1024  # 5 MB


class FormatError(Exception):
    """Raised when a file is not a supported format or is malformed."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_size(path: str) -> int:
    """Return file size, raising if missing or oversized."""
    if not os.path.isfile(path):
        raise FormatError(f"file not found: {path}")
    size = os.path.getsize(path)
    if size == 0:
        raise FormatError(f"empty file: {path}")
    if size > MAX_FILE_SIZE:
        raise FormatError(
            f"file too large ({size} bytes > {MAX_FILE_SIZE} bytes): {path}"
        )
    return size


def _read_magic(path: str, n: int = 4) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


# ---------------------------------------------------------------------------
# PE (Windows EXE / DLL)
# ---------------------------------------------------------------------------

def inspect_pe(path: str) -> Dict[str, Any]:
    """Extract static info from a PE file (EXE or DLL)."""
    try:
        import pefile
    except ImportError as exc:
        raise FormatError("pefile library not installed; PE analysis unavailable") from exc

    _safe_size(path)
    try:
        pe = pefile.PE(path)
    except Exception as exc:
        raise FormatError(f"not a valid PE file: {exc}") from exc

    try:
        # Architecture / machine
        machine = pe.FILE_HEADER.Machine
        arch_map = {
            0x014C: "x86 (i386)",
            0x8664: "x64 (amd64)",
            0x01C0: "ARM",
            0xAA64: "ARM64",
        }
        architecture = arch_map.get(machine, f"unknown (0x{machine:04X})")

        # DLL vs EXE
        characteristics = pe.FILE_HEADER.Characteristics
        is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL
        file_type = "DLL" if is_dll else "EXE"

        # Imports
        imports: List[Dict[str, Any]] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", "replace") if isinstance(entry.dll, bytes) else str(entry.dll)
                funcs: List[str] = []
                for imp in entry.imports:
                    if imp.name is not None:
                        funcs.append(imp.name.decode("utf-8", "replace") if isinstance(imp.name, bytes) else str(imp.name))
                    elif imp.ordinal is not None:
                        funcs.append(f"ordinal:{imp.ordinal}")
                imports.append({"dll": dll_name, "functions": funcs[:50], "function_count": len(funcs)})

        # Exports (DLLs)
        exports: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is not None:
                    exports.append(exp.name.decode("utf-8", "replace") if isinstance(exp.name, bytes) else str(exp.name))

        # Dependencies (DLLs the PE links against)
        dependencies = [imp["dll"] for imp in imports]

        # Entry point
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint if hasattr(pe, "OPTIONAL_HEADER") else None
        image_base = pe.OPTIONAL_HEADER.ImageBase if hasattr(pe, "OPTIONAL_HEADER") else None

        # Sections
        sections = []
        for sec in pe.sections:
            sections.append({
                "name": sec.Name.decode("utf-8", "replace").rstrip("\x00"),
                "virtual_address": sec.VirtualAddress,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
            })

        return {
            "format": "pe",
            "file_type": file_type,
            "architecture": architecture,
            "machine_hex": f"0x{machine:04X}",
            "is_dll": is_dll,
            "entry_point": f"0x{entry_point:08X}" if entry_point is not None else None,
            "image_base": f"0x{image_base:08X}" if image_base is not None else None,
            "sections": sections[:20],
            "section_count": len(sections),
            "imports": imports[:20],
            "import_dll_count": len(imports),
            "dependencies": dependencies[:30],
            "dependency_count": len(dependencies),
            "exports": exports[:50],
            "export_count": len(exports),
        }
    finally:
        pe.close()


# ---------------------------------------------------------------------------
# APK (Android)
# ---------------------------------------------------------------------------

def inspect_apk(path: str) -> Dict[str, Any]:
    """Extract static info from an APK file."""
    _safe_size(path)

    if not zipfile.is_zipfile(path):
        raise FormatError("not a valid ZIP/APK file")

    result: Dict[str, Any] = {
        "format": "apk",
        "package_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "max_sdk": None,
        "version_code": None,
        "version_name": None,
        "permissions": [],
        "permission_count": 0,
        "native_libraries": [],
        "native_library_count": 0,
        "dex_files": [],
        "dex_count": 0,
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "has_native_code": False,
        "entry_points": [],
    }

    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = zf.namelist()
            if len(names) > MAX_ZIP_ENTRIES:
                raise FormatError(f"too many ZIP entries ({len(names)} > {MAX_ZIP_ENTRIES})")

            # Native libraries
            native = [n for n in names if n.endswith(".so") and ("lib/" in n or n.startswith("lib/"))]
            result["native_libraries"] = sorted(native)[:100]
            result["native_library_count"] = len(native)
            result["has_native_code"] = len(native) > 0

            # DEX files
            dex = [n for n in names if n.endswith(".dex")]
            result["dex_files"] = sorted(dex)[:50]
            result["dex_count"] = len(dex)

            # Manifest
            if "AndroidManifest.xml" in names:
                manifest_data = zf.read("AndroidManifest.xml")
                if len(manifest_data) > MAX_APK_MANIFEST_SIZE:
                    raise FormatError("AndroidManifest.xml too large")
                _parse_apk_manifest(result, manifest_data)
    except FormatError:
        raise
    except Exception as exc:
        raise FormatError(f"failed to parse APK: {exc}") from exc

    return result


def _parse_apk_manifest(result: Dict[str, Any], data: bytes) -> None:
    """Parse AndroidManifest.xml (binary XML or plain text)."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        # Binary XML (aapt2 compiled) - cannot parse with ElementTree directly.
        # Fall back to regex-based extraction of readable strings.
        _parse_apk_manifest_regex(result, data)
        return

    ns = {"android": "http://schemas.android.com/apk/res/android"}

    def attr(name: str) -> Optional[str]:
        return root.get(f"{{{ns['android']}}}{name}")

    result["package_name"] = root.get("package") or attr("package")
    result["version_code"] = attr("versionCode")
    result["version_name"] = attr("versionName")
    result["min_sdk"] = attr("minSdkVersion")
    result["target_sdk"] = attr("targetSdkVersion")
    result["max_sdk"] = attr("maxSdkVersion")

    # Permissions (uses-permission)
    perms = []
    for elem in root.iter("uses-permission"):
        name = elem.get(f"{{{ns['android']}}}name") or attr_impl(elem, "name", ns)
        if name:
            perms.append(name)
    result["permissions"] = perms[:200]
    result["permission_count"] = len(perms)

    # Components
    for comp_tag, result_key in (("activity", "activities"), ("service", "services"),
                                  ("receiver", "receivers"), ("provider", "providers")):
        items = []
        for elem in root.iter(comp_tag):
            name = elem.get(f"{{{ns['android']}}}name") or attr_impl(elem, "name", ns)
            if name:
                items.append(name)
        result[result_key] = items[:100]

    # Entry points: activities with MAIN intent filter
    entry_points = []
    for app in root.iter("application"):
        for act in app.iter("activity"):
            for intent in act.iter("intent-filter"):
                for action in intent.iter("action"):
                    act_name = action.get(f"{{{ns['android']}}}name") or attr_impl(action, "name", ns)
                    if act_name and "android.intent.action.MAIN" in act_name:
                        act_label = act.get(f"{{{ns['android']}}}name") or attr_impl(act, "name", ns)
                        if act_label:
                            entry_points.append(act_label)
    result["entry_points"] = entry_points[:50]


def attr_impl(elem: ET.Element, name: str, ns: Dict[str, str]) -> Optional[str]:
    return elem.get(f"{{{ns['android']}}}{name}")


def _parse_apk_manifest_regex(result: Dict[str, Any], data: bytes) -> None:
    """Fallback regex extraction for binary (uncompiled) AndroidManifest.xml."""
    text = data.decode("utf-8", "replace")
    # package
    m = re.search(r'package="([^"]+)"', text)
    if m:
        result["package_name"] = m.group(1)
    m = re.search(r'versionCode="([^"]+)"', text)
    if m:
        result["version_code"] = m.group(1)
    m = re.search(r'versionName="([^"]+)"', text)
    if m:
        result["version_name"] = m.group(1)
    m = re.search(r'minSdkVersion="([^"]+)"', text)
    if m:
        result["min_sdk"] = m.group(1)
    m = re.search(r'targetSdkVersion="([^"]+)"', text)
    if m:
        result["target_sdk"] = m.group(1)

    # permissions
    perms = re.findall(r'android:name="([^"]*permission[^"]*)"', text)
    result["permissions"] = sorted(set(perms))[:200]
    result["permission_count"] = len(result["permissions"])

    # components
    for tag, key in (("activity", "activities"), ("service", "services"),
                      ("receiver", "receivers"), ("provider", "providers")):
        names = re.findall(rf'<{tag}[^>]*android:name="([^"]+)"', text)
        result[key] = sorted(set(names))[:100]


# ---------------------------------------------------------------------------
# Kotlin source (.kt)
# ---------------------------------------------------------------------------

_KOTLIN_PACKAGE_RE = re.compile(r"^\s*package\s+([\w\.]+)", re.MULTILINE)
_KOTLIN_IMPORT_RE = re.compile(r"^\s*import\s+([\w\.]+)", re.MULTILINE)
_KOTLIN_CLASS_RE = re.compile(r"(?:class|interface|object|enum class|sealed class|annotation class)\s+([\w]+)", re.MULTILINE)
_KOTLIN_FUN_RE = re.compile(r"(?:suspend\s+)?fun\s+([\w]+)\s*\([^)]*\)(?:\s*[:<]\s*[^{]+)?", re.MULTILINE)


def inspect_kt(path: str) -> Dict[str, Any]:
    """Extract static info from a Kotlin source file."""
    _safe_size(path)
    if os.path.getsize(path) > MAX_KOTLIN_SIZE:
        raise FormatError(f"Kotlin file too large: {path}")

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as exc:
        raise FormatError(f"cannot read Kotlin file: {exc}") from exc

    package_m = _KOTLIN_PACKAGE_RE.search(content)
    package = package_m.group(1) if package_m else None

    imports = _KOTLIN_IMPORT_RE.findall(content)
    classes = _KOTLIN_CLASS_RE.findall(content)
    functions = _KOTLIN_FUN_RE.findall(content)

    # Detect common integration hints
    integration_hints: List[str] = []
    lower = content.lower()
    if "fun main" in lower:
        integration_hints.append("has main entry point")
    if "@jvmstatic" in lower:
        integration_hints.append("has @JvmStatic (Java interop)")
    if "@jvmname" in lower:
        integration_hints.append("has @JvmName (Java interop)")
    if "external" in lower:
        integration_hints.append("has external declarations (native/FFI)")
    if "plugin" in lower:
        integration_hints.append("mentions 'plugin'")
    if "android" in lower:
        integration_hints.append("mentions 'android'")

    return {
        "format": "kotlin",
        "package": package,
        "imports": imports[:100],
        "import_count": len(imports),
        "classes": classes[:100],
        "class_count": len(classes),
        "functions": functions[:100],
        "function_count": len(functions),
        "integration_hints": integration_hints,
        "file_path": path,
    }


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

def detect_format(path: str) -> str:
    """Return 'pe', 'apk', 'kotlin', or 'unknown'."""
    _safe_size(path)
    magic = _read_magic(path, 4)
    if magic[:2] == MAGIC_PE:
        return "pe"
    if magic[:4] == MAGIC_APK_ZIP:
        return "apk"
    if path.lower().endswith(".kt"):
        return "kotlin"
    return "unknown"


def inspect_file(path: str) -> Dict[str, Any]:
    """Dispatch inspection by detected format."""
    fmt = detect_format(path)
    if fmt == "pe":
        return inspect_pe(path)
    if fmt == "apk":
        return inspect_apk(path)
    if fmt == "kotlin":
        return inspect_kt(path)
    raise FormatError(f"unsupported or unknown file format: {path}")
