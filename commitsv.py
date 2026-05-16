import argparse
import sys
from pathlib import Path

from core.scanner import scan_directory
from output.console import (
    print_scan_start,
    print_no_findings,
    print_findings,
    set_color_enabled
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CommitSV - Git secret scanner for projects"
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan. Default: current directory"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output"
    )

    args = parser.parse_args()

    set_color_enabled(not args.no_color)

    scan_path = Path(args.path).resolve()

    if not scan_path.exists():
        print(f"[ERROR] Path does not exist: {scan_path}")
        return 2

    if not scan_path.is_dir():
        print(f"[ERROR] Path is not a directory: {scan_path}")
        return 2

    print_scan_start(str(scan_path))

    findings = scan_directory(scan_path)

    if not findings:
        print_no_findings()
        return 0

    print_findings(findings)
    return 1


if __name__ == "__main__":
    sys.exit(main())
