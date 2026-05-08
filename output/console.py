from core.models import Finding


SEVERITY_ORDER = {
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}


def print_scan_start(path: str) -> None:
    print(f"[INFO] Scanning: {path}")


def print_no_findings() -> None:
    print("[OK] No potential secrets found.")


def print_findings(findings: list[Finding]) -> None:
    sorted_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(finding.severity, 99)
    )

    print()
    print(f"[WARNING] Found {len(sorted_findings)} potential secret(s):")
    print()

    for finding in sorted_findings:
        print_finding(finding)

    print_summary(sorted_findings)


def print_finding(finding: Finding) -> None:
    print(f"[{finding.severity}] {finding.rule_name}")
    print(f"  File: {finding.file_path}")
    print(f"  Line: {finding.line_number}")
    print(f"  Match: {finding.matched_text}")
    print()


def print_summary(findings: list[Finding]) -> None:
    high_count = count_by_severity(findings, "HIGH")
    medium_count = count_by_severity(findings, "MEDIUM")
    low_count = count_by_severity(findings, "LOW")

    print("[SUMMARY]")
    print(f"  HIGH:   {high_count}")
    print(f"  MEDIUM: {medium_count}")
    print(f"  LOW:    {low_count}")
    print()
    print("[RESULT] Potential secrets found. Review before committing.")


def count_by_severity(findings: list[Finding], severity: str) -> int:
    return sum(1 for finding in findings if finding.severity == severity)
