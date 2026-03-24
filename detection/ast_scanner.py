"""
AST-Based Static Analysis Scanner for Insecure Deserialization
===============================================================
Uses Python's built-in `ast` module to parse source files and detect
dangerous deserialization patterns:

  1. pickle.loads()  / pickle.load()   — arbitrary code execution
  2. yaml.load()     without SafeLoader — arbitrary code execution
  3. marshal.loads() / shelve.open()    — less common but still dangerous

The scanner outputs a structured report with file, line number, severity,
and remediation advice for each finding.

Usage:
    python detection/ast_scanner.py [path ...]

    If no paths are given, it scans the app/ directory by default.
"""

import ast
import json
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    file: str
    line: int
    col: int
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    category: str          # e.g. "insecure-deserialization"
    pattern: str           # e.g. "pickle.loads"
    message: str
    remediation: str


# ---------------------------------------------------------------------------
# AST Visitor that detects dangerous patterns
# ---------------------------------------------------------------------------
class DeserializationVisitor(ast.NodeVisitor):
    """Walk an AST and collect insecure deserialization findings."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: list[Finding] = []
        # Track imports so we can resolve aliases (e.g. import pickle as pk)
        self._import_aliases: dict[str, str] = {}

    # ---- Track imports ----
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self._import_aliases[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            name = alias.asname or alias.name
            self._import_aliases[name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    # ---- Detect dangerous calls ----
    def visit_Call(self, node: ast.Call):
        func_name = self._resolve_call(node.func)
        if func_name:
            self._check_pickle(node, func_name)
            self._check_yaml(node, func_name)
            self._check_marshal(node, func_name)
            self._check_shelve(node, func_name)
        self.generic_visit(node)

    # ---- Pattern checkers ----
    def _check_pickle(self, node: ast.Call, func_name: str):
        dangerous = {"pickle.loads", "pickle.load", "_pickle.loads", "_pickle.load"}
        if func_name in dangerous:
            self.findings.append(Finding(
                file=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity="CRITICAL",
                category="insecure-deserialization",
                pattern=func_name,
                message=(
                    f"Call to {func_name}() on potentially untrusted data. "
                    "pickle can execute arbitrary code during deserialization."
                ),
                remediation="Use json.loads() or a restricted unpickler instead of pickle.",
            ))

    def _check_yaml(self, node: ast.Call, func_name: str):
        if func_name not in ("yaml.load", "yaml.unsafe_load"):
            return

        if func_name == "yaml.unsafe_load":
            self.findings.append(Finding(
                file=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity="CRITICAL",
                category="insecure-deserialization",
                pattern=func_name,
                message=f"Call to {func_name}() allows arbitrary Python object instantiation.",
                remediation="Use yaml.safe_load() instead.",
            ))
            return

        # yaml.load — check if a safe Loader keyword is used
        safe_loaders = {"SafeLoader", "yaml.SafeLoader", "BaseLoader", "yaml.BaseLoader"}
        loader_is_safe = False

        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute):
                    loader_name = f"{self._get_name(kw.value.value)}.{kw.value.attr}"
                    if loader_name in safe_loaders:
                        loader_is_safe = True
                elif isinstance(kw.value, ast.Name):
                    if kw.value.id in safe_loaders:
                        loader_is_safe = True

        if not loader_is_safe:
            self.findings.append(Finding(
                file=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity="HIGH",
                category="insecure-deserialization",
                pattern=func_name,
                message=(
                    f"Call to {func_name}() without SafeLoader. "
                    "FullLoader and UnsafeLoader allow code execution via YAML tags."
                ),
                remediation="Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
            ))

    def _check_marshal(self, node: ast.Call, func_name: str):
        if func_name in ("marshal.loads", "marshal.load"):
            self.findings.append(Finding(
                file=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity="HIGH",
                category="insecure-deserialization",
                pattern=func_name,
                message=f"Call to {func_name}() — marshal is not safe for untrusted data.",
                remediation="Use json.loads() for data exchange.",
            ))

    def _check_shelve(self, node: ast.Call, func_name: str):
        if func_name == "shelve.open":
            self.findings.append(Finding(
                file=self.filepath,
                line=node.lineno,
                col=node.col_offset,
                severity="HIGH",
                category="insecure-deserialization",
                pattern=func_name,
                message="shelve.open() uses pickle internally — unsafe for untrusted data.",
                remediation="Use a proper database (SQLite, etc.) instead of shelve.",
            ))

    # ---- Helpers ----
    def _resolve_call(self, node) -> str | None:
        """Try to resolve a call node to a dotted name like 'pickle.loads'."""
        if isinstance(node, ast.Attribute):
            value_name = self._get_name(node.value)
            if value_name:
                # Resolve import alias
                module = self._import_aliases.get(value_name, value_name)
                return f"{module}.{node.attr}"
        elif isinstance(node, ast.Name):
            return self._import_aliases.get(node.id, node.id)
        return None

    @staticmethod
    def _get_name(node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{DeserializationVisitor._get_name(node.value)}.{node.attr}"
        return None


# ---------------------------------------------------------------------------
# Scanner entry point
# ---------------------------------------------------------------------------
def scan_file(filepath: str) -> list[Finding]:
    """Parse a single Python file and return findings."""
    with open(filepath, "r", encoding="utf-8") as f:
        source = f.read()
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError as exc:
        print(f"  [SKIP] Syntax error in {filepath}: {exc}", file=sys.stderr)
        return []
    visitor = DeserializationVisitor(filepath)
    visitor.visit(tree)
    return visitor.findings


def scan_paths(paths: list[str]) -> list[Finding]:
    """Recursively scan directories and files, returning all findings."""
    all_findings: list[Finding] = []
    for path in paths:
        p = Path(path)
        if p.is_file() and p.suffix == ".py":
            all_findings.extend(scan_file(str(p)))
        elif p.is_dir():
            for pyfile in sorted(p.rglob("*.py")):
                all_findings.extend(scan_file(str(pyfile)))
        else:
            print(f"  [SKIP] Not a .py file or directory: {path}", file=sys.stderr)
    return all_findings


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[96m",  # cyan
    "LOW":      "\033[92m",  # green
}
RESET = "\033[0m"


def print_report(findings: list[Finding]):
    """Print a human-readable report to stdout."""
    print("\n" + "=" * 70)
    print("  AST Static Analysis Report — Insecure Deserialization")
    print("=" * 70)

    if not findings:
        print("\n  No insecure deserialization patterns found.\n")
        return

    print(f"\n  Total findings: {len(findings)}\n")

    for i, f in enumerate(findings, 1):
        color = SEVERITY_COLORS.get(f.severity, "")
        print(f"  [{i}] {color}{f.severity}{RESET}  {f.pattern}")
        print(f"      File: {f.file}:{f.line}:{f.col}")
        print(f"      {f.message}")
        print(f"      Fix:  {f.remediation}")
        print()

    # Summary
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    print("  " + "-" * 40)
    print("  Summary:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in by_sev:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {color}{sev}{RESET}: {by_sev[sev]}")
    print()


def export_json(findings: list[Finding], output_path: str):
    """Export findings as a JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([asdict(fd) for fd in findings], f, indent=2)
    print(f"  JSON report saved to: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    paths = sys.argv[1:] if len(sys.argv) > 1 else ["app/", "exploits/"]

    print(f"Scanning: {', '.join(paths)}")
    findings = scan_paths(paths)
    print_report(findings)

    # Also export JSON report
    report_dir = Path("detection")
    report_dir.mkdir(exist_ok=True)
    export_json(findings, str(report_dir / "scan_results.json"))


if __name__ == "__main__":
    main()
