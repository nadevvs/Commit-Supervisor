from core.models import Finding


SEVERITY_ORDER = {
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}

USE_COLOR = True

COLOR_RESET = "\033[0m"

COLOR_RED = "\033[31m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_YELLOW = "\033[33m"
COLOR_GREEN = "\033[32m"
COLOR_BLUE = "\033[34m"


def set_color_enabled(enabled: bool) -> None:
    global USE_COLOR
    USE_COLOR = enabled


def colored_label(label: str, color: str) -> str:
    if not USE_COLOR:
        return f"[{label}]"

    return f"[{color}{label}{COLOR_RESET}]"


def get_severity_color(severity: str) -> str:
    if severity == "HIGH":
        return COLOR_RED

    if severity == "MEDIUM":
        return COLOR_ORANGE

    if severity == "LOW":
        return COLOR_YELLOW

    return COLOR_RESET


def print_scan_start(path: str) -> None:
    print(f"{colored_label('INFO', COLOR_BLUE)} Scanning: {path}")


def print_no_findings() -> None:
    print(f"{colored_label('OK', COLOR_GREEN)} No potential secrets found.")


def print_findings(findings: list[Finding]) -> None:
    sorted_findings = sorted(
        findings,
        key=lambda finding: SEVERITY_ORDER.get(finding.severity, 99)
    )

    print()
    print(f"{colored_label('WARNING', COLOR_ORANGE)} Found {len(sorted_findings)} potential secret(s):")
    print()

    for finding in sorted_findings:
        print_finding(finding)

    print_summary(sorted_findings)


def print_finding(finding: Finding) -> None:
    color = get_severity_color(finding.severity)

    print(f"{colored_label(finding.severity, color)} {finding.rule_name}")
    print(f"  File: {finding.file_path}")
    print(f"  Line: {finding.line_number}")
    print(f"  Match: {finding.matched_text}")
    print()


def print_summary(findings: list[Finding]) -> None:
    high_count = count_by_severity(findings, "HIGH")
    medium_count = count_by_severity(findings, "MEDIUM")
    low_count = count_by_severity(findings, "LOW")

    print(f"{colored_label('SUMMARY', COLOR_BLUE)}")
    print(f"  {colored_label('HIGH', COLOR_RED)}   {high_count}")
    print(f"  {colored_label('MEDIUM', COLOR_ORANGE)} {medium_count}")
    print(f"  {colored_label('LOW', COLOR_YELLOW)}    {low_count}")
    print()
    print(f"{colored_label('RESULT', COLOR_ORANGE)} Potential secrets found. Review before committing.")


def count_by_severity(findings: list[Finding], severity: str) -> int:
    return sum(1 for finding in findings if finding.severity == severity)
