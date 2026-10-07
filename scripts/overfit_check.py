"""Fail if agent code or prompts mention scenario-specific values seen in recorded runs.

The current runs are the dev stage; the prod stage uses unseen, mutated scenarios. Hostnames,
account names, IPs, hashes, ids and non-system file names from recorded alerts and tool results
must never appear in `src/`. Generic Windows/Linux binaries and paths are allowed.

Usage: uv run python scripts/overfit_check.py
"""

import contextlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "bluesec1_agent"
PROPERTY_KEYS = {"hostname", "user", "ip", "sha256", "sha1", "md5", "remote_ip", "dest_ip"}
GENERIC = re.compile(
    r"^(c:\\windows\\|c:\\program files|/usr/|/bin/|/etc/|nt authority|system$|local service)", re.I
)


def collect_values(value: object, found: set[str]) -> None:
    """Collect scenario-specific strings from recorded JSON."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("id", "entity_id", "relation_id", "source_id", "target_id") and isinstance(
                item, str
            ):
                found.add(item)
            elif key in PROPERTY_KEYS and isinstance(item, str) and len(item) >= 5:
                if not GENERIC.match(item):
                    found.add(item.split("\\")[-1])
            elif key in ("image_path", "path") and isinstance(item, str):
                if GENERIC.match(item):
                    continue
                name = re.split(r"[\\/]", item)[-1]
                if len(name) >= 6:
                    found.add(name)
            collect_values(item, found)
    elif isinstance(value, list):
        for item in value:
            collect_values(item, found)
    elif isinstance(value, str) and value[:1] in "{[":
        with contextlib.suppress(json.JSONDecodeError):
            collect_values(json.loads(value), found)


def main() -> int:
    """Scan recorded runs, then grep agent sources for the collected values."""
    found: set[str] = set()
    for path in (ROOT / "runs").glob("*/observations.jsonl"):
        for line in path.open(encoding="utf-8"):
            collect_values(json.loads(line), found)
    for path in (ROOT / "runs").glob("*/steps.jsonl"):
        for line in path.open(encoding="utf-8"):
            collect_values(json.loads(line).get("result"), found)
    sources = {p: p.read_text(encoding="utf-8").lower() for p in SOURCE.rglob("*.py")}
    # Plain dictionary words ("command", "system") are not scenario-specific.
    specific = {v for v in found if re.search(r"[\d._@$-]", v) or len(v) >= 12}
    hits = sorted(
        (str(p.relative_to(ROOT)), value)
        for value in specific
        for p, text in sources.items()
        if re.search(rf"(?<![\w.\\/-]){re.escape(value.lower())}(?![\w-])", text)
    )
    for path, value in hits:
        print(f"OVERFIT RISK: {path} mentions scenario value {value!r}")
    print(f"checked {len(specific)} specific recorded values against {len(sources)} source files")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
