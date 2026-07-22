#!/usr/bin/env python3
"""
Generate k8s/panops/manifests/assembler/assembler-cm.yaml from docker/assembler/src/*.py.

Run from the repo root:
    python tools/gen-assembler-cm.py [--check]

--check: diff against an existing CM file; exit 1 if different (CI drift gate).
         Requires --homelab-cm to specify the path to the homelab CM file.
"""
import argparse
import os
import sys

SRC_DIR  = os.path.join(os.path.dirname(__file__), "..", "docker", "assembler", "src")
FILES    = [
    "assembler.py", "classifier.py", "consolidation.py", "correlator.py",
    "drain3_detector.py", "remediator.py", "runbook_writer.py",
]
CM_HEADER = """\
apiVersion: v1
kind: ConfigMap
metadata:
  name: panops-assembler-script
  namespace: panops
data:
"""


def generate():
    lines = [CM_HEADER]
    for fname in FILES:
        path = os.path.join(SRC_DIR, fname)
        with open(path) as f:
            content = f.read()
        lines.append(f"  {fname}: |\n")
        for line in content.splitlines():
            lines.append(f"    {line}\n" if line else "\n")
        lines.append("\n")
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="diff against an existing file; exit 1 if stale")
    parser.add_argument("--homelab-cm", default=None,
                        help="path to homelab assembler-cm.yaml (required with --check)")
    args = parser.parse_args()

    generated = generate()

    if args.check:
        if not args.homelab_cm:
            print("--check requires --homelab-cm <path>", file=sys.stderr)
            sys.exit(2)
        try:
            with open(args.homelab_cm) as f:
                on_disk = f.read()
        except FileNotFoundError:
            print(f"CM file not found: {args.homelab_cm}", file=sys.stderr)
            sys.exit(1)
        if generated != on_disk:
            import difflib
            diff = list(difflib.unified_diff(
                on_disk.splitlines(keepends=True),
                generated.splitlines(keepends=True),
                fromfile="homelab/assembler-cm.yaml",
                tofile="generated-from-source",
                n=3,
            ))
            print("".join(diff[:60]))
            print(f"\nassembler-cm.yaml is stale. Run: python tools/gen-assembler-cm.py > <path>")
            sys.exit(1)
        print("assembler-cm.yaml is up to date.")
        return

    sys.stdout.write(generated)


if __name__ == "__main__":
    main()
