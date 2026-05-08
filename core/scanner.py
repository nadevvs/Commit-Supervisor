import re
from pathlib import Path

from core.ignore import should_skip_path, is_binary_file
from core.models import Finding
from core.rules import SECRET_RULES
from core.utils import mask_secret, safe_read_text


def scan_directory(root_path: Path) -> list[Finding]:
    findings = []

    for path in root_path.rglob("*"):
        if not path.is_file():
            continue

        file_findings = scan_file(path)
        findings.extend(file_findings)

    return findings


def scan_file(path: Path) -> list[Finding]:
    findings = []

    if should_skip_path(path):
        return findings

    if is_binary_file(path):
        return findings

    content = safe_read_text(path)

    if content is None:
        return findings

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        line_findings = scan_line(path, line_number, line)
        findings.extend(line_findings)

    return findings


def scan_line(path: Path, line_number: int, line: str) -> list[Finding]:
    findings = []

    for rule in SECRET_RULES:
        pattern = re.compile(rule.pattern)
        match = pattern.search(line)

        if match:
            findings.append(
                Finding(
                    file_path=str(path),
                    line_number=line_number,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    matched_text=mask_secret(line)
                )
            )

    return findings
