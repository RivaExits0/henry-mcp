"""Analysis workflow and scenario generation for henry-mcp.

All analysis is static and read-only. Conclusions are expressed as
evidence-backed inferences, never as definitive runtime claims.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from formats import inspect_file as _formats_inspect_file, detect_format, FormatError
from reports import Report, Finding, ReportStore, new_finding_id, paginate

# Architecture compatibility groups
ARCH_GROUPS = {
    "x86 (i386)": {"x86", "i386", "x86 (i386)"},
    "x64 (amd64)": {"x64", "amd64", "x64 (amd64)"},
    "ARM": {"arm", "ARM"},
    "ARM64": {"arm64", "aarch64", "ARM64"},
}

# Common Windows runtime DLLs that are usually present
COMMON_WINDOWS_DLLS = {
    "kernel32.dll", "user32.dll", "gdi32.dll", "advapi32.dll",
    "ole32.dll", "comdlg32.dll", "shell32.dll", "shlwapi.dll",
    "msvcrt.dll", "ntdll.dll", "version.dll",
}

# Common Android ABIs
ANDROID_ABIS = {"armeabi-v7a", "arm64-v8a", "x86", "x86_64"}


class Analyzer:
    """Static compatibility analyzer for app + module pairs."""

    def __init__(self) -> None:
        self.store = ReportStore()
        self._last_session_id: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Public tools
    # ------------------------------------------------------------------ #

    def inspect_file(self, path: str, limit: int = 1000, offset: int = 0) -> Dict[str, Any]:
        """Inspect a single file and return a structured static report.

        Args:
            path: File path to inspect.
            limit: Maximum number of findings to return.
            offset: Number of findings to skip.
        """
        fmt = detect_format(path)
        info = _formats_inspect_file(path)

        report = Report(
            summary=f"Static inspection of {os.path.basename(path)} ({fmt}).",
            format=fmt,
            file=path,
        )

        # Observed findings
        if fmt == "pe":
            self._add_pe_findings(report, info)
        elif fmt == "apk":
            self._add_apk_findings(report, info)
        elif fmt == "kotlin":
            self._add_kt_findings(report, info)

        report.warnings.append(
            "This is a static report only. It does not execute, inject, or modify any file."
        )
        report.limitations.append(
            "Static analysis cannot guarantee runtime behaviour. "
            "Actual loading and invocation must be verified at runtime."
        )

        self._finalize(report)
        out = report.to_dict()
        out["info"] = info
        # Apply pagination to findings
        page = paginate(out["findings"], limit, offset)
        out["findings"] = page["items"]
        out["pagination"] = {
            "total": page["total"],
            "offset": page["offset"],
            "limit": page["limit"],
            "returned": page["returned"],
            "has_more": page["has_more"],
        }
        return out

    def analyze_pair(self, app_path: str, module_path: str,
                     limit: int = 1000, offset: int = 0) -> Dict[str, Any]:
        """Compare an application file with a module file for compatibility.

        Args:
            app_path: Path to the application file.
            module_path: Path to the module file.
            limit: Maximum number of findings to return.
            offset: Number of findings to skip.
        """
        app_info = _formats_inspect_file(app_path)
        module_info = _formats_inspect_file(module_path)

        app_fmt = app_info.get("format")
        module_fmt = module_info.get("format")

        report = Report(
            summary=f"Pair analysis: {os.path.basename(app_path)} + {os.path.basename(module_path)}.",
            format="pair",
            file=f"{app_path} + {module_path}",
        )

        # 1. Format / platform compatibility
        self._compare_format(report, app_info, module_info)

        # 2. Architecture / ABI
        self._compare_architecture(report, app_info, module_info)

        # 3. Dependencies / exports / imports
        self._compare_symbols(report, app_info, module_info)

        # 4. Integration conditions
        self._integration_conditions(report, app_info, module_info)

        report.warnings.append(
            "Compatibility is an inference from static structure, not a guarantee."
        )
        report.limitations.append(
            "No files are loaded or executed. Runtime linking behaviour is not tested."
        )

        self._finalize(report)
        out = report.to_dict()
        out["app_info"] = app_info
        out["module_info"] = module_info
        # Apply pagination to findings
        page = paginate(out["findings"], limit, offset)
        out["findings"] = page["items"]
        out["pagination"] = {
            "total": page["total"],
            "offset": page["offset"],
            "limit": page["limit"],
            "returned": page["returned"],
            "has_more": page["has_more"],
        }
        return out

    def predict_failure_scenarios(self, app_path: str, module_path: str,
                                  limit: int = 1000, offset: int = 0) -> Dict[str, Any]:
        """Produce evidence-backed failure scenarios for an app + module pair.

        Args:
            app_path: Path to the application file.
            module_path: Path to the module file.
            limit: Maximum number of scenarios to return.
            offset: Number of scenarios to skip.
        """
        app_info = _formats_inspect_file(app_path)
        module_info = _formats_inspect_file(module_path)

        app_fmt = app_info.get("format")
        module_fmt = module_info.get("format")

        scenarios: List[Dict[str, Any]] = []

        if app_fmt == "pe" and module_fmt == "pe":
            scenarios = self._pe_failure_scenarios(app_info, module_info)
        elif app_fmt == "apk" and module_fmt == "apk":
            scenarios = self._apk_failure_scenarios(app_info, module_info)
        elif app_fmt == "apk" and module_fmt == "pe":
            scenarios = self._apk_pe_failure_scenarios(app_info, module_info)
        elif app_fmt == "apk" and module_fmt == "kotlin":
            scenarios = self._apk_kt_failure_scenarios(app_info, module_info)
        elif app_fmt == "pe" and module_fmt == "kotlin":
            scenarios = [
                self._scenario(
                    title="Cross-platform mismatch: PE app with Kotlin module",
                    condition="The application is a Windows PE binary and the module is Kotlin source.",
                    symptom="The module cannot be loaded or linked by the Windows application.",
                    cause="Different executable formats and runtimes (Windows PE vs Kotlin/JVM/Android).",
                    evidence=[
                        f"app format: {app_info.get('file_type')} (PE)",
                        f"module format: {module_info.get('format')} (Kotlin source)",
                    ],
                    severity="high",
                    confidence="high",
                    validation_needed="Confirm intended platform; use a matching module type.",
                )
            ]
        else:
            scenarios = [
                self._scenario(
                    title="Unsupported format combination",
                    condition=f"App format '{app_fmt}' with module format '{module_fmt}' is not analysed.",
                    symptom="No compatibility assessment can be made.",
                    cause="The analyser does not support this format pairing.",
                    evidence=[
                        f"app: {app_path} ({app_fmt})",
                        f"module: {module_path} ({module_fmt})",
                    ],
                    severity="low",
                    confidence="high",
                    validation_needed="Provide a supported format pair (EXE+DLL, APK+Kotlin, APK+native lib).",
                )
            ]

        # If no scenarios were generated, add a "no issues detected" note
        if not scenarios:
            scenarios.append({
                "title": "No compatibility issues detected",
                "condition": "Static analysis found no obvious mismatches.",
                "symptom": "None expected based on static structure alone.",
                "cause": "No conflicting findings were identified.",
                "evidence": [
                    f"app={app_info.get('format')}, module={module_info.get('format')}",
                    "No architecture mismatch, missing dependency, or export issues found.",
                ],
                "severity": "low",
                "confidence": "low",
                "validation_needed": "Runtime testing required: verify by actually loading and invoking the module.",
            })

        report = Report(
            summary=f"Failure scenarios for {os.path.basename(app_path)} + {os.path.basename(module_path)}.",
            format="scenarios",
            file=f"{app_path} + {module_path}",
        )
        report.findings = [
            Finding(
                id=new_finding_id(),
                type="scenario",
                file=app_path,
                field="failure_scenarios",
                observed_value=None,
                inferred_value=None,
                confidence=s["confidence"],
                evidence=s["evidence"],
                notes=None,
            )
            for s in scenarios
        ]
        # Attach scenarios as a separate field for easy consumption
        out = report.to_dict()
        page = paginate(scenarios, limit, offset)
        out["scenarios"] = page["items"]
        out["pagination"] = {
            "total": page["total"],
            "offset": page["offset"],
            "limit": page["limit"],
            "returned": page["returned"],
            "has_more": page["has_more"],
        }
        return out

    def explain_finding(self, finding_id: str) -> Dict[str, Any]:
        """Explain a previously produced finding by ID."""
        finding = self.store.get_finding(finding_id)
        if finding is None:
            return {
                "error": f"finding not found: {finding_id}",
                "hint": "Call henry_inspect_file, henry_analyze_pair, or henry_predict_failure_scenarios first.",
            }
        return {
            "finding_id": finding.id,
            "type": finding.type,
            "file": finding.file,
            "field": finding.field,
            "observed_value": finding.observed_value,
            "inferred_value": finding.inferred_value,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "notes": finding.notes,
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _finalize(self, report: Report) -> None:
        session_id = new_finding_id()
        self.store.add_report(session_id, report)
        self._last_session_id = session_id

    def reset(self) -> Dict[str, Any]:
        """Clear all stored reports and findings."""
        count = len(self.store._findings)
        self.store._reports.clear()
        self.store._findings.clear()
        self._last_session_id = None
        return {"cleared_findings": count}

    def _add_pe_findings(self, report: Report, info: Dict[str, Any]) -> None:
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="format", observed_value="pe",
            inferred_value="Windows PE executable",
            confidence="high",
            evidence=["MZ magic bytes detected", "PE headers parsed"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="file_type", observed_value=info.get("file_type"),
            confidence="high",
            evidence=[f"IMAGE_FILE_DLL characteristic: {info.get('is_dll')}"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="architecture", observed_value=info.get("architecture"),
            confidence="high",
            evidence=[f"Machine field: {info.get('machine_hex')}"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="dependencies", observed_value=info.get("dependencies"),
            confidence="medium",
            evidence=[f"Imported DLLs: {', '.join(info.get('dependencies', [])[:10])}"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="exports", observed_value=info.get("export_count"),
            confidence="high",
            evidence=[f"Exported symbols: {info.get('export_count')}"],
        ))

    def _add_apk_findings(self, report: Report, info: Dict[str, Any]) -> None:
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="package_name", observed_value=info.get("package_name"),
            confidence="high" if info.get("package_name") else "low",
            evidence=["AndroidManifest.xml package attribute"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="sdk", observed_value={
                "min": info.get("min_sdk"),
                "target": info.get("target_sdk"),
                "max": info.get("max_sdk"),
            },
            confidence="high",
            evidence=["AndroidManifest.xml uses-sdk attributes"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="permissions", observed_value=info.get("permissions", [])[:20],
            confidence="high",
            evidence=[f"{info.get('permission_count')} permissions declared"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="native_libraries", observed_value=info.get("native_libraries", [])[:20],
            confidence="high",
            evidence=[f"{info.get('native_library_count')} .so files in APK"],
        ))

    def _add_kt_findings(self, report: Report, info: Dict[str, Any]) -> None:
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="package", observed_value=info.get("package"),
            confidence="medium" if info.get("package") else "low",
            evidence=["package declaration parsed from source"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="classes", observed_value=info.get("classes", [])[:20],
            confidence="high",
            evidence=[f"{info.get('class_count')} class/interface/object declarations"],
        ))
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="functions", observed_value=info.get("functions", [])[:20],
            confidence="high",
            evidence=[f"{info.get('function_count')} function declarations"],
        ))

    def _compare_format(self, report: Report, app: Dict[str, Any], module: Dict[str, Any]) -> None:
        app_fmt = app.get("format")
        mod_fmt = module.get("format")

        supported_pairs = {
            ("pe", "pe"): "EXE/DLL on Windows",
            ("apk", "kotlin"): "Android app + Kotlin source",
            ("apk", "pe"): "Android app + native library (PE)",
        }
        pair = (app_fmt, mod_fmt)
        if pair in supported_pairs:
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="format_pair", observed_value=pair,
                inferred_value=f"Supported pair: {supported_pairs[pair]}",
                confidence="high",
                evidence=[f"app={app_fmt}, module={mod_fmt}"],
            ))
        else:
            report.findings.append(Finding(
                id=new_finding_id(), type="warning", file=report.file,
                field="format_pair", observed_value=pair,
                inferred_value="Not a directly supported format combination",
                confidence="high",
                evidence=[f"app={app_fmt}, module={mod_fmt}"],
            ))

    def _compare_architecture(self, report: Report, app: Dict[str, Any], module: Dict[str, Any]) -> None:
        if app.get("format") != "pe" or module.get("format") != "pe":
            return
        app_arch = app.get("architecture", "")
        mod_arch = module.get("architecture", "")
        same = self._arch_same(app_arch, mod_arch)
        report.findings.append(Finding(
            id=new_finding_id(), type="observation", file=report.file,
            field="architecture_match", observed_value={"app": app_arch, "module": mod_arch},
            inferred_value="architectures match" if same else "architecture mismatch",
            confidence="high" if app_arch and mod_arch else "medium",
            evidence=[f"app machine: {app.get('machine_hex')}", f"module machine: {module.get('machine_hex')}"],
        ))

    def _compare_symbols(self, report: Report, app: Dict[str, Any], module: Dict[str, Any]) -> None:
        if app.get("format") == "pe" and module.get("format") == "pe":
            app_deps = set(d.lower() for d in app.get("dependencies", []))
            mod_deps = set(d.lower() for d in module.get("dependencies", []))
            mod_exports = module.get("exports", [])

            # DLLs that the module needs but the app does not import
            missing_from_app = sorted(mod_deps - app_deps - COMMON_WINDOWS_DLLS)

            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="module_exports", observed_value=mod_exports[:50],
                confidence="high",
                evidence=[f"{module.get('export_count')} exported symbols in DLL"],
            ))
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="app_dependencies", observed_value=app.get("dependencies", [])[:30],
                confidence="high",
                evidence=[f"{app.get('dependency_count')} imported DLLs in EXE"],
            ))
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="module_dependencies", observed_value=module.get("dependencies", [])[:30],
                confidence="high",
                evidence=[f"{module.get('dependency_count')} imported DLLs in module"],
            ))
            if missing_from_app:
                report.findings.append(Finding(
                    id=new_finding_id(), type="inference", file=report.file,
                    field="missing_module_dependencies", observed_value=missing_from_app,
                    inferred_value=(
                        "The module imports DLLs that the application does not reference. "
                        "These must be present on the system for the module to load."
                    ),
                    confidence="medium",
                    evidence=[f"Module-only imports: {', '.join(missing_from_app)}"],
                ))

        elif app.get("format") == "apk" and module.get("format") == "kotlin":
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="kotlin_package", observed_value=module.get("package"),
                confidence="medium",
                evidence=[f"Kotlin package: {module.get('package')}"],
            ))
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="apk_package", observed_value=app.get("package_name"),
                confidence="high",
                evidence=[f"APK package: {app.get('package_name')}"],
            ))

        elif app.get("format") == "apk" and module.get("format") == "pe":
            # APK + native library (PE/DLL or .so inside APK context)
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="app_package", observed_value=app.get("package_name"),
                confidence="high",
                evidence=[f"APK package: {app.get('package_name')}"],
            ))
            report.findings.append(Finding(
                id=new_finding_id(), type="observation", file=report.file,
                field="module_architecture", observed_value=module.get("architecture"),
                confidence="high",
                evidence=[f"Module architecture: {module.get('architecture')}"],
            ))
            report.findings.append(Finding(
                id=new_finding_id(), type="inference", file=report.file,
                field="native_abi_match", observed_value=None,
                inferred_value=(
                    "Android native libraries must match the APK's target ABI "
                    "(armeabi-v7a, arm64-v8a, x86, x86_64). PE modules are Windows "
                    "binaries and cannot be loaded directly by Android."
                ),
                confidence="high",
                evidence=[f"module format: {module.get('file_type')} ({module.get('architecture')})"],
            ))

    def _integration_conditions(self, report: Report, app: Dict[str, Any], module: Dict[str, Any]) -> None:
        if app.get("format") == "apk" and module.get("format") == "pe":
            report.findings.append(Finding(
                id=new_finding_id(), type="warning", file=report.file,
                field="integration_condition", observed_value=None,
                inferred_value=(
                    "Android cannot load a Windows PE DLL directly. "
                    "For Android, the native module must be an ELF .so file "
                    "matching the device ABI, packaged inside the APK under "
                    "lib/<abi>/ and loaded via System.loadLibrary()."
                ),
                confidence="high",
                evidence=["Android native library loading requirements"],
            ))
            return

        report.findings.append(Finding(
            id=new_finding_id(), type="warning", file=report.file,
            field="integration_condition", observed_value=None,
            inferred_value=(
                "Copying a module file next to the application does not cause it to be loaded. "
                "The application must explicitly load the module (e.g., LoadLibrary/GetProcAddress "
                "for DLLs, System.loadLibrary for native libs, or classpath inclusion for Kotlin)."
            ),
            confidence="high",
            evidence=["General Windows/Android loading semantics"],
        ))

    def _arch_same(self, a: str, b: str) -> bool:
        if not a or not b:
            return False
        a_lower = a.lower()
        b_lower = b.lower()
        if a_lower == b_lower:
            return True
        for group in ARCH_GROUPS.values():
            if a_lower in group and b_lower in group:
                return True
        return False

    # ------------------------------------------------------------------ #
    # Failure scenarios
    # ------------------------------------------------------------------ #

    def _scenario(self, title: str, condition: str, symptom: str, cause: str,
                  evidence: List[str], severity: str, confidence: str,
                  validation_needed: str) -> Dict[str, Any]:
        return {
            "title": title,
            "condition": condition,
            "symptom": symptom,
            "cause": cause,
            "evidence": evidence,
            "severity": severity,
            "confidence": confidence,
            "validation_needed": validation_needed,
        }

    def _pe_failure_scenarios(self, app: Dict[str, Any], module: Dict[str, Any]) -> List[Dict[str, Any]]:
        scenarios: List[Dict[str, Any]] = []

        # Architecture mismatch
        app_arch = app.get("architecture", "")
        mod_arch = module.get("architecture", "")
        if not self._arch_same(app_arch, mod_arch):
            scenarios.append(self._scenario(
                title="Architecture mismatch between EXE and DLL",
                condition=f"App is {app_arch}, module is {mod_arch}.",
                symptom="LoadLibrary fails with ERROR_BAD_EXE_FORMAT (0xC1) or the process crashes on load.",
                cause="Windows cannot load a DLL built for a different CPU architecture into a process.",
                evidence=[
                    f"app architecture: {app_arch} ({app.get('machine_hex')})",
                    f"module architecture: {mod_arch} ({module.get('machine_hex')})",
                ],
                severity="high",
                confidence="high",
                validation_needed="Rebuild the DLL for the same architecture as the EXE.",
            ))

        # Missing dependency
        app_deps = set(d.lower() for d in app.get("dependencies", []))
        mod_deps = set(d.lower() for d in module.get("dependencies", []))
        missing = [d for d in mod_deps if d not in app_deps and d not in COMMON_WINDOWS_DLLS]
        if missing:
            scenarios.append(self._scenario(
                title="DLL dependency not present in application's import set",
                condition=f"The DLL imports {missing} which the EXE does not reference.",
                symptom="LoadLibrary or GetProcAddress fails; the DLL may fail to initialize.",
                cause="The DLL requires a runtime DLL that is not part of the application's known dependency set.",
                evidence=[f"DLL imports: {sorted(missing)}"],
                severity="medium",
                confidence="medium",
                validation_needed="Verify the required runtime DLL is deployed alongside the application.",
            ))

        # No exports (unlikely to be useful as a plugin)
        if module.get("export_count", 0) == 0:
            scenarios.append(self._scenario(
                title="DLL has no exported functions",
                condition="The DLL exports zero symbols.",
                symptom="GetProcAddress returns NULL for any function name; the module is not callable.",
                cause="No exported entry points means no way for the application to invoke DLL code.",
                evidence=[f"module export_count: {module.get('export_count')}"],
                severity="high",
                confidence="high",
                validation_needed="Add __declspec(dllexport) or a .def file to the DLL.",
            ))

        # Mechanism missing
        scenarios.append(self._scenario(
            title="No explicit DLL-loading mechanism detected in the EXE",
            condition="The EXE import table does not obviously reference LoadLibrary/GetProcAddress.",
            symptom="Even if placed next to the EXE, the DLL is not loaded automatically.",
            cause="Static analysis cannot confirm the EXE has code to locate and load the DLL.",
            evidence=[
                f"EXE imports: {[i['dll'] for i in app.get('imports', [])][:10]}",
                "No static evidence of a plugin loader",
            ],
            severity="medium",
            confidence="low",
            validation_needed="Search the EXE for LoadLibrary / GetProcAddress calls or plugin registration code.",
        ))

        return scenarios

    def _apk_failure_scenarios(self, app: Dict[str, Any], module: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            self._scenario(
                title="APK+APK pair not a standard integration pattern",
                condition="Both files are APK archives.",
                symptom="No clear mechanism to load one APK inside another.",
                cause="APKs are installation packages, not linkable modules.",
                evidence=[f"app={app.get('package_name')}, module={module.get('package_name')}"],
                severity="low",
                confidence="high",
                validation_needed="Use APK + Kotlin source or APK + native library instead.",
            )
        ]

    def _apk_pe_failure_scenarios(self, app: Dict[str, Any], module: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [
            self._scenario(
                title="PE module cannot be loaded by Android APK",
                condition="The module is a Windows PE binary but the app is an Android APK.",
                symptom="The module cannot be loaded or linked by the Android application.",
                cause="Android runs ELF native libraries (.so), not Windows PE binaries (.dll/.exe).",
                evidence=[
                    f"app format: apk ({app.get('package_name')})",
                    f"module format: pe ({module.get('file_type')}, {module.get('architecture')})",
                ],
                severity="high",
                confidence="high",
                validation_needed="Provide an ELF .so native library built for the target Android ABI.",
            )
        ]

    def _apk_kt_failure_scenarios(self, app: Dict[str, Any], module: Dict[str, Any]) -> List[Dict[str, Any]]:
        scenarios: List[Dict[str, Any]] = []

        # Package mismatch
        app_pkg = app.get("package_name")
        kt_pkg = module.get("package")
        if app_pkg and kt_pkg and app_pkg != kt_pkg and not kt_pkg.startswith(app_pkg + "."):
            scenarios.append(self._scenario(
                title="Kotlin package does not match APK package",
                condition=f"APK package={app_pkg}, Kotlin package={kt_pkg}.",
                symptom="ClassNotFoundException or unresolved reference at build/runtime.",
                cause="Kotlin source in a different package may not resolve against the app's classes.",
                evidence=[f"APK package: {app_pkg}", f"Kotlin package: {kt_pkg}"],
                severity="medium",
                confidence="medium",
                validation_needed="Align package names or add the Kotlin module to the app's source set.",
            ))

        # No main / entry hint
        if "has main entry point" not in module.get("integration_hints", []):
            scenarios.append(self._scenario(
                title="Kotlin module lacks an obvious entry point",
                condition="No 'fun main' detected in the Kotlin source.",
                symptom="Unclear how the application would invoke Kotlin code.",
                cause="Static analysis cannot identify a callable integration point.",
                evidence=[f"Kotlin functions: {module.get('functions', [])[:10]}"],
                severity="low",
                confidence="low",
                validation_needed="Add an explicit entry function or plugin interface implementation.",
            ))

        # Missing Android mention (if app is Android)
        if "android" not in module.get("integration_hints", []):
            scenarios.append(self._scenario(
                title="Kotlin source does not reference Android APIs",
                condition="No 'android' mention detected in the Kotlin source.",
                symptom="The module may not compile against the Android SDK or may not integrate with the APK.",
                cause="Android integration typically requires android.* imports.",
                evidence=[f"integration_hints: {module.get('integration_hints')}"],
                severity="medium",
                confidence="low",
                validation_needed="Confirm the Kotlin file is meant for the Android target and add android.* imports if needed.",
            ))

        return scenarios
