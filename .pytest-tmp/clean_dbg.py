from pathlib import Path

path = Path("src/secval/code_processing/code_splitting/python/split_python_declarations.py")
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
kept = []
skip_next = 0
for index, line in enumerate(lines):
    if skip_next:
        skip_next -= 1
        continue
    if "DBG" in line:
        # DBG left 调试跨两行，第二行以 | right: 开头。
        if "DBG left" in line:
            skip_next = 1
        continue
    if line.strip() == "import sys as _sys":
        continue
    kept.append(line)
path.write_text("".join(kept), encoding="utf-8")
print("cleaned")
