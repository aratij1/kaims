"""Remove reproducible workspace caches; preview by default.

Application data, reports, dependencies, secrets and temporary working scripts
are deliberately outside this command's scope.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHES = {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
SKIP = {".git", ".venv", "node_modules", "external", "artifacts", ".tmp",
        "data", "host-evidence", "retention-archives", "ingested_alerts"}


def candidates(root: Path):
    for base, directories, _ in os.walk(root, followlinks=False):
        for name in list(directories):
            path = Path(base, name)
            if path.is_symlink() or path.is_junction() or name in SKIP:
                directories.remove(name)
            elif name in CACHES:
                directories.remove(name)
                yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Delete the listed caches")
    args = parser.parse_args()
    results = []
    for path in candidates(ROOT):
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(ROOT) or resolved == ROOT:
            raise ValueError(f"Cache outside workspace: {path}")
        # Never traverse a redirected directory inside a cache during deletion.
        redirected = any(
            Path(base, name).is_symlink() or Path(base, name).is_junction()
            for base, directories, files in os.walk(path, followlinks=False)
            for name in directories + files
        )
        if redirected:
            continue
        size = sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
        if args.apply:
            shutil.rmtree(path)
        results.append({"path": str(path.relative_to(ROOT)), "bytes": size})
    print(json.dumps({"applied": args.apply, "directories": len(results),
                      "bytes": sum(item["bytes"] for item in results),
                      "caches": results}, indent=2))


if __name__ == "__main__":
    main()
