"""MCP end-to-end smoke test for henry-mcp."""

import asyncio
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from test_henry import make_pe_exe, make_pe_dll, make_apk, make_kt, FIXTURE_DIR


def _fixture(name: str, maker) -> str:
    p = os.path.join(FIXTURE_DIR, name)
    maker(p)
    return p


def test_mcp_smoke():
    exe = _fixture("smoke_exe.exe", make_pe_exe)
    dll = _fixture("smoke_dll.dll", make_pe_dll)
    apk = _fixture("smoke.apk", make_apk)
    kt = _fixture("smoke.kt", make_kt)

    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def main():
        params = StdioServerParameters(command="python3", args=["server.py"], cwd=ROOT)
        async with stdio_client(params) as (r, w):
            async with ClientSession(r, w) as s:
                await s.initialize()

                # List tools
                tools = await s.list_tools()
                names = [t.name for t in tools.tools]
                assert all(n in names for n in [
                    "henry_inspect_file", "henry_analyze_pair",
                    "henry_predict_failure_scenarios", "henry_explain_finding",
                    "henry_reset",
                ])

                # henry_inspect_file on EXE
                res = await s.call_tool("henry_inspect_file", {"path": exe})
                d = json.loads(res.content[0].text)
                info = d.get("info", d)
                assert info["format"] == "pe"
                assert info["file_type"] in ("EXE", "DLL")

                # henry_inspect_file on APK
                res = await s.call_tool("henry_inspect_file", {"path": apk})
                d = json.loads(res.content[0].text)
                info = d.get("info", d)
                assert info["format"] == "apk"
                assert info["package_name"] == "com.example.testapp"

                # henry_inspect_file on Kotlin
                res = await s.call_tool("henry_inspect_file", {"path": kt})
                d = json.loads(res.content[0].text)
                info = d.get("info", d)
                assert info["format"] == "kotlin"

                # henry_analyze_pair EXE + DLL
                res = await s.call_tool("henry_analyze_pair",
                                        {"app_path": exe, "module_path": dll})
                d = json.loads(res.content[0].text)
                assert d["format"] == "pair"
                fields = {f["field"] for f in d["findings"]}
                assert "architecture_match" in fields

                # Get a finding ID from the report for explain test
                finding_id = None
                for f in d["findings"]:
                    if f.get("field") == "architecture_match":
                        finding_id = f["id"]
                        break
                assert finding_id is not None

                # henry_explain_finding
                res = await s.call_tool("henry_explain_finding",
                                        {"finding_id": finding_id})
                d2 = json.loads(res.content[0].text)
                assert d2["finding_id"] == finding_id

                # henry_predict_failure_scenarios
                res = await s.call_tool("henry_predict_failure_scenarios",
                                        {"app_path": exe, "module_path": dll})
                d3 = json.loads(res.content[0].text)
                assert "scenarios" in d3
                assert isinstance(d3["scenarios"], list)

                # henry_explain_finding with nonexistent ID
                res = await s.call_tool("henry_explain_finding",
                                        {"finding_id": "nonexistent"})
                d4 = json.loads(res.content[0].text)
                assert "error" in d4

                # henry_reset
                res = await s.call_tool("henry_reset", {})
                d5 = json.loads(res.content[0].text)
                assert "cleared_findings" in d5

    asyncio.run(main())
    print("MCP SMOKE TEST PASSED")


if __name__ == "__main__":
    test_mcp_smoke()
