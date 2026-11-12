"""Tests for henry-mcp.

Fixtures are generated in-memory or via the system compiler; no user-owned
EXE/APK files are required.
"""

import os
import sys
import json
import struct
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from formats import detect_format, inspect_file, FormatError
from analyzer import Analyzer


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

FIXTURE_DIR = os.path.join(ROOT, "tests", "fixtures")


def _ensure_fixtures():
    os.makedirs(FIXTURE_DIR, exist_ok=True)


def make_pe_exe(path: str) -> str:
    """Write a minimal PE EXE stub (parseable by pefile)."""
    _write_minimal_pe(path, is_dll=False)
    return path


def make_pe_dll(path: str) -> str:
    """Write a minimal PE DLL stub (parseable by pefile)."""
    _write_minimal_pe(path, is_dll=True)
    return path


def _write_minimal_pe(path: str, is_dll: bool) -> None:
    """Write a minimal, parseable PE file (MZ + PE header)."""
    # DOS header + PE signature + COFF + Optional header (392 bytes total)
    pe = bytearray(0x188)
    pe[0:2] = b"MZ"
    struct.pack_into("<H", pe, 0x3C, 0x80)  # e_lfanew -> PE signature at 0x80

    # PE signature at 0x80
    pe[0x80:0x84] = b"PE\x00\x00"

    # COFF header starts at 0x84
    coff_start = 0x84
    machine = 0x8664  # x64
    num_sections = 0
    timestamp = 0
    ptr_symtab = 0
    num_symtab = 0
    sizeof_opt = 0xF0  # PE32+
    characteristics = 0x2000 if is_dll else 0x0002
    struct.pack_into("<HHIIIHH", pe, coff_start,
                     machine, num_sections, timestamp, ptr_symtab,
                     num_symtab, sizeof_opt, characteristics)

    # Optional header starts at 0x84 + 20 = 0x98
    opt_start = coff_start + 20

    struct.pack_into("<H", pe, opt_start, 0x20B)  # magic PE32+
    struct.pack_into("<BB", pe, opt_start + 2, 0, 0)  # linker version
    struct.pack_into("<II", pe, opt_start + 4, 0, 0)  # code/data size
    struct.pack_into("<H", pe, opt_start + 16, 0)  # subsystem
    struct.pack_into("<Q", pe, opt_start + 24, 0x140001000)  # image base
    struct.pack_into("<I", pe, opt_start + 32, 0x1000)  # section alignment
    struct.pack_into("<I", pe, opt_start + 36, 0x200)  # file alignment
    struct.pack_into("<H", pe, opt_start + 40, 6)  # OS version
    struct.pack_into("<H", pe, opt_start + 42, 0)  # image version
    struct.pack_into("<H", pe, opt_start + 44, 0)  # subsystem version
    struct.pack_into("<I", pe, opt_start + 60, 0x1000)  # size of image
    struct.pack_into("<I", pe, opt_start + 64, 0x200)  # size of headers
    struct.pack_into("<I", pe, opt_start + 68, 0)  # checksum
    struct.pack_into("<H", pe, opt_start + 72, 3)  # subsystem = console
    struct.pack_into("<H", pe, opt_start + 74, 0)  # DLL characteristics
    struct.pack_into("<Q", pe, opt_start + 76, 0x1000)  # stack reserve
    struct.pack_into("<Q", pe, opt_start + 84, 0x1000)  # stack commit
    struct.pack_into("<Q", pe, opt_start + 92, 0x1000)  # heap reserve
    struct.pack_into("<Q", pe, opt_start + 100, 0x1000)  # heap commit
    struct.pack_into("<I", pe, opt_start + 108, 0)  # loader flags
    struct.pack_into("<I", pe, opt_start + 112, 16)  # num rva sizes
    # data directories (16 x 8 bytes) - all zero, already padded

    with open(path, "wb") as f:
        f.write(pe)


def make_apk(path: str) -> str:
    """Create a minimal APK fixture (ZIP + AndroidManifest.xml)."""
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest package="com.example.testapp"\n'
        '  xmlns:android="http://schemas.android.com/apk/res/android"\n'
        '  android:versionCode="1"\n'
        '  android:versionName="1.0"\n'
        '  android:minSdkVersion="21"\n'
        '  android:targetSdkVersion="34">\n'
        '  <uses-permission android:name="android.permission.INTERNET"/>\n'
        '  <uses-permission android:name="android.permission.CAMERA"/>\n'
        '  <application>\n'
        '    <activity android:name=".MainActivity">\n'
        '      <intent-filter>\n'
        '        <action android:name="android.intent.action.MAIN"/>\n'
        '      </intent-filter>\n'
        '    </activity>\n'
        '  </application>\n'
        '</manifest>\n'
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\x0a\x00\x00\x00")
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF fake")
    return path


def make_kt(path: str) -> str:
    """Create a Kotlin source fixture."""
    content = (
        'package com.example.testapp\n'
        '\n'
        'import androidx.appcompat.app.AppCompatActivity\n'
        'import android.os.Bundle\n'
        '\n'
        '@JvmStatic\n'
        'fun main(args: Array<String>) {\n'
        '    println("hello")\n'
        '}\n'
        '\n'
        'class Calculator {\n'
        '    fun add(a: Int, b: Int): Int = a + b\n'
        '}\n'
    )
    with open(path, "w") as f:
        f.write(content)
    return path


def make_unsupported(path: str) -> str:
    with open(path, "wb") as f:
        f.write(b"\x7fELF not-a-real-pe-or-apk" * 10)
    return path


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #

def test_detect_pe_exe():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "test_exe.exe")
    make_pe_exe(p)
    fmt = detect_format(p)
    assert fmt == "pe", fmt


def test_detect_pe_dll():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "test_dll.dll")
    make_pe_dll(p)
    fmt = detect_format(p)
    assert fmt == "pe", fmt


def test_detect_apk():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "test.apk")
    make_apk(p)
    fmt = detect_format(p)
    assert fmt == "apk", fmt


def test_detect_kt():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "test.kt")
    make_kt(p)
    fmt = detect_format(p)
    assert fmt == "kotlin", fmt


def test_inspect_pe_exe():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "inspect_exe.exe")
    make_pe_exe(p)
    info = inspect_file(p)
    assert info["format"] == "pe"
    assert info["file_type"] in ("EXE", "DLL")
    assert info["architecture"] is not None
    assert "dependencies" in info
    assert "exports" in info


def test_inspect_apk():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "inspect.apk")
    make_apk(p)
    info = inspect_file(p)
    assert info["format"] == "apk"
    assert info["package_name"] == "com.example.testapp"
    assert info["min_sdk"] == "21"
    assert info["target_sdk"] == "34"
    assert "android.permission.INTERNET" in info["permissions"]
    assert info["dex_count"] == 1
    assert info["native_library_count"] == 1


def test_inspect_kt():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "inspect.kt")
    make_kt(p)
    info = inspect_file(p)
    assert info["format"] == "kotlin"
    assert info["package"] == "com.example.testapp"
    assert info["class_count"] >= 1
    assert info["function_count"] >= 1


def test_unsupported_format():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "unsupported.bin")
    make_unsupported(p)
    try:
        inspect_file(p)
        assert False, "expected FormatError"
    except FormatError:
        pass


def test_pair_pe_same_arch():
    _ensure_fixtures()
    exe = os.path.join(FIXTURE_DIR, "pair_exe.exe")
    dll = os.path.join(FIXTURE_DIR, "pair_dll.dll")
    make_pe_exe(exe)
    make_pe_dll(dll)
    a = Analyzer()
    result = a.analyze_pair(exe, dll)
    assert result["format"] == "pair"
    fields = {f["field"] for f in result["findings"]}
    assert "architecture_match" in fields
    arch_f = [f for f in result["findings"] if f["field"] == "architecture_match"][0]
    assert arch_f["inferred_value"] == "architectures match"


def test_pair_apk_pe():
    """APK + PE pair should be flagged as incompatible."""
    _ensure_fixtures()
    apk = os.path.join(FIXTURE_DIR, "pair_apk.apk")
    pe = os.path.join(FIXTURE_DIR, "pair_pe.dll")
    make_apk(apk)
    make_pe_dll(pe)
    a = Analyzer()
    result = a.analyze_pair(apk, pe)
    assert result["format"] == "pair"
    fields = {f["field"] for f in result["findings"]}
    assert "format_pair" in fields
    assert "native_abi_match" in fields


def test_predict_failure_scenarios_pe():
    _ensure_fixtures()
    exe = os.path.join(FIXTURE_DIR, "pred_exe.exe")
    dll = os.path.join(FIXTURE_DIR, "pred_dll.dll")
    make_pe_exe(exe)
    make_pe_dll(dll)
    a = Analyzer()
    result = a.predict_failure_scenarios(exe, dll)
    assert "scenarios" in result
    assert isinstance(result["scenarios"], list)
    assert len(result["scenarios"]) >= 1


def test_predict_failure_scenarios_apk_pe():
    """APK + PE should produce a cross-platform failure scenario."""
    _ensure_fixtures()
    apk = os.path.join(FIXTURE_DIR, "pred_apk.apk")
    pe = os.path.join(FIXTURE_DIR, "pred_pe.dll")
    make_apk(apk)
    make_pe_dll(pe)
    a = Analyzer()
    result = a.predict_failure_scenarios(apk, pe)
    assert "scenarios" in result
    assert len(result["scenarios"]) >= 1
    titles = [s["title"] for s in result["scenarios"]]
    assert any("PE" in t or "pe" in t.lower() for t in titles)


def test_explain_finding_roundtrip():
    """A finding produced by inspect_file should be explainable by ID."""
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "explain.exe")
    make_pe_exe(p)
    a = Analyzer()
    result = a.inspect_file(p)
    # Find a finding ID from the report
    finding_id = None
    for f in result.get("findings", []):
        if f.get("field") == "architecture":
            finding_id = f["id"]
            break
    assert finding_id is not None, "no architecture finding produced"
    explained = a.explain_finding(finding_id)
    assert explained["finding_id"] == finding_id
    assert explained["field"] == "architecture"


def test_explain_finding_nonexistent():
    a = Analyzer()
    result = a.explain_finding("nonexistent")
    assert "error" in result


def test_reset_clears_findings():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "reset.exe")
    make_pe_exe(p)
    a = Analyzer()
    a.inspect_file(p)
    assert len(a.store._findings) > 0
    cleared = a.reset()
    assert cleared["cleared_findings"] > 0
    assert len(a.store._findings) == 0


def test_low_confidence_no_evidence():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "lowconf.kt")
    make_kt(p)
    with open(p, "w") as f:
        f.write("fun foo() {}\n")
    info = inspect_file(p)
    assert info["package"] is None


def test_pagination():
    from reports import paginate
    items = list(range(25))
    page = paginate(items, limit=10, offset=0)
    assert page["total"] == 25
    assert page["returned"] == 10
    assert page["offset"] == 0
    assert page["has_more"] is True
    page2 = paginate(items, limit=10, offset=20)
    assert page2["returned"] == 5
    assert page2["has_more"] is False


def test_file_not_modified():
    """Verify the analyzer does not modify input files."""
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "readonly.exe")
    make_pe_exe(p)
    with open(p, "rb") as f:
        before = f.read()
    size_before = os.path.getsize(p)
    mtime_before = os.path.getmtime(p)

    a = Analyzer()
    a.inspect_file(p)
    a.analyze_pair(p, p)

    with open(p, "rb") as f:
        after = f.read()
    assert before == after, "file content was modified"
    assert os.path.getsize(p) == size_before
    assert os.path.getmtime(p) == mtime_before


def test_oversized_file_rejected():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "oversized.bin")
    with open(p, "wb") as f:
        f.write(b"\x00" * (250 * 1024 * 1024))  # 250 MB > 200 MB limit
    try:
        detect_format(p)
        assert False, "expected FormatError for oversized file"
    except FormatError:
        pass
    finally:
        os.remove(p)


def test_empty_file_rejected():
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "empty.bin")
    with open(p, "wb") as f:
        f.write(b"")
    try:
        detect_format(p)
        assert False, "expected FormatError for empty file"
    except FormatError:
        pass
    finally:
        os.remove(p)


def test_nonexistent_file_rejected():
    try:
        detect_format("/no/such/file.exe")
        assert False, "expected FormatError for nonexistent file"
    except FormatError:
        pass


def test_inspect_file_pagination():
    """Test that inspect_file paginates findings."""
    _ensure_fixtures()
    p = os.path.join(FIXTURE_DIR, "pag_exe.exe")
    make_pe_exe(p)
    a = Analyzer()

    # First page
    result = a.inspect_file(p, limit=2, offset=0)
    assert "pagination" in result
    assert result["pagination"]["limit"] == 2
    assert result["pagination"]["offset"] == 0
    assert result["pagination"]["returned"] <= 2
    assert result["pagination"]["total"] > 0
    assert len(result["findings"]) <= 2

    # Second page (if there are more findings)
    if result["pagination"]["has_more"]:
        result2 = a.inspect_file(p, limit=2, offset=2)
        assert result2["pagination"]["offset"] == 2
        assert len(result2["findings"]) <= 2


def test_analyze_pair_pagination():
    """Test that analyze_pair paginates findings."""
    _ensure_fixtures()
    exe = os.path.join(FIXTURE_DIR, "pag_exe.exe")
    dll = os.path.join(FIXTURE_DIR, "pag_dll.dll")
    make_pe_exe(exe)
    make_pe_dll(dll)
    a = Analyzer()

    result = a.analyze_pair(exe, dll, limit=1, offset=0)
    assert "pagination" in result
    assert result["pagination"]["limit"] == 1
    assert result["pagination"]["returned"] <= 1
    assert len(result["findings"]) <= 1


def test_predict_failure_scenarios_pagination():
    """Test that predict_failure_scenarios paginates scenarios."""
    _ensure_fixtures()
    exe = os.path.join(FIXTURE_DIR, "pag_exe2.exe")
    dll = os.path.join(FIXTURE_DIR, "pag_dll2.dll")
    make_pe_exe(exe)
    make_pe_dll(dll)
    a = Analyzer()

    result = a.predict_failure_scenarios(exe, dll, limit=1, offset=0)
    assert "pagination" in result
    assert result["pagination"]["limit"] == 1
    assert result["pagination"]["returned"] <= 1
    assert len(result["scenarios"]) <= 1
