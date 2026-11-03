#!/usr/bin/env python3
"""Validate fenced Markdown and README TOC targets without extra dependencies."""
from pathlib import Path
import re
import sys
from urllib.parse import unquote

def check(path):
    in_fence = False
    anchors = set()
    targets = []
    errors = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if re.match(r"^ {0,3}`{3}", line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r"^(#{1,6}) (.+)$", line)
        if match:
            title = re.sub(r"<[^>]*>", "", match.group(2)).replace("`", "").replace("*", "").lower()
            title = "".join(c for c in title if c.isalnum() or c.isspace() or c in "_-")
            anchor = re.sub(r"\s", "-", title)
            if anchor in anchors:
                errors.append(f"{path}:{number}: duplicate anchor #{anchor}")
            anchors.add(anchor)
        if line.lstrip().startswith("- ["):
            targets += [unquote(target) for target in re.findall(r"\]\(#([^)]*)\)", line)]
    if in_fence:
        errors.append(f"{path}: unclosed fenced code block")
    if len(targets) < 10:
        errors.append(f"{path}: missing TOC links")
    for target in targets:
        if target not in anchors:
            errors.append(f"{path}: broken TOC link #{target}")
    return errors

errors = [e for f in ("README.md", "README.ja.md") for e in check(f)]
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("README Markdown structure OK")
