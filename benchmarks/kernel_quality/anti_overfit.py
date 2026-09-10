"""Fail when benchmark-only identifiers leak into production runtime code."""

import argparse
import json
from pathlib import Path

RUNTIME_SUFFIXES = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".java"})


def find_leaks(runtime_root, identifiers):
    root = Path(runtime_root).resolve()
    leaks = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in RUNTIME_SUFFIXES:
            continue
        content = path.read_text(encoding="utf-8")
        for identifier in identifiers:
            if identifier and identifier in content:
                leaks.append({"path": path.relative_to(root).as_posix(),
                              "identifier": identifier})
    return leaks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", default="src/secval")
    parser.add_argument("--identifiers", default="benchmarks/kernel_quality/forbidden-identifiers.txt")
    args = parser.parse_args()
    identifiers = [line.strip() for line in Path(args.identifiers).read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.lstrip().startswith("#")]
    leaks = find_leaks(args.runtime, identifiers)
    print(json.dumps({"checked_identifiers": len(identifiers), "leaks": leaks}, ensure_ascii=False))
    raise SystemExit(1 if leaks else 0)


if __name__ == "__main__":
    main()
