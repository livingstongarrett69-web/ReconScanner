import json
import sys
from core.scan_diff import ScanDiff
from reporting.diff_report import DiffReporter


def main():

    if len(sys.argv) < 3:
        print("Usage: python scan_compare.py old_scan.json new_scan.json")
        return

    with open(sys.argv[1]) as f:
        old_scan = json.load(f)

    with open(sys.argv[2]) as f:
        new_scan = json.load(f)

    diff = ScanDiff().compare(old_scan, new_scan)

    file = DiffReporter().save(diff)

    print("Diff report saved:", file)


if __name__ == "__main__":
    main()