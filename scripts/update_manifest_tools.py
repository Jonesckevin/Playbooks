#!/usr/bin/env python3
"""Scan playbooks-main/ and populate the manifest tools[] field.

Reads every playbook JSON file referenced in the manifest and records which
tool platforms have at least one non-empty query.  No queries are generated or
modified - this is a read-only scan that updates only the "tools" index in the
manifest so the frontend can display tool-coverage pips without loading each
individual playbook file.

Usage: python scripts/update_manifest_tools.py
"""
from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path

# ── Setup logging for visibility ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_MAIN = ROOT / "app" / "playbooks-main"
MANIFEST_PATH = PLAYBOOK_MAIN / "manifest.json"

KNOWN_TOOLS = {
    "splunk", "kql", "security_onion", "qradar", "sigma", "sysmon",
    "velociraptor", "osquery", "carbon_black", "elastic", "chronicle",
    "crowdstrike", "defender", "opensearch", "logrhythm",
}

# Investigation field names to scan (both legacy and current formats)
INVESTIGATION_SECTIONS = [
    # Current format
    ("investigation", "detectionAnalysis"),
    ("investigation", "containment"),
    ("investigation", "eradication"),
    ("investigation", "recovery"),
    # Legacy flat format
    ("detSteps", None),
    ("contSteps", None),
    ("eradSteps", None),
    ("recSteps", None),
]


def has_value(v) -> bool:
    """Return True if a query value is non-empty/non-null."""
    if v is None:
        return False
    s = str(v).strip()
    return bool(s) and s.lower() not in ("none", "null", "{}", "[]")


def extract_tools(pb: dict) -> list[str]:
    """Return sorted list of tool keys that have at least one non-empty query."""
    found: set[str] = set()

    for parent_key, child_key in INVESTIGATION_SECTIONS:
        section = pb.get(parent_key)
        if section is None:
            continue
        if child_key:
            steps = section.get(child_key) if isinstance(section, dict) else None
        else:
            steps = section

        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue
            queries = step.get("queries") or {}
            if not isinstance(queries, dict):
                continue
            for tool, value in queries.items():
                if tool in KNOWN_TOOLS and has_value(value):
                    found.add(tool)

    return sorted(found)


def main() -> int:
    try:
        logger.info("Scanning playbooks to update manifest tools...")
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        updated = skipped = missing = 0

        for entry in manifest.get("playbooks", []):
            rel_file = entry.get("file", "")
            if not rel_file:
                skipped += 1
                continue

            pb_path = PLAYBOOK_MAIN / rel_file
            if not pb_path.exists():
                # File may not exist yet (e.g. reference-only entries)
                entry["tools"] = entry.get("tools") or []
                missing += 1
                continue

            try:
                pb = json.loads(pb_path.read_text(encoding="utf-8"))
                tools = extract_tools(pb)
                entry["tools"] = tools
                updated += 1
            except Exception as exc:
                logger.warning(f"Could not read {rel_file}: {exc}")
                entry["tools"] = entry.get("tools") or []
                skipped += 1

        manifest["generated"] = date.today().isoformat()
        MANIFEST_PATH.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        logger.info(f"Manifest tools updated: {updated}  skipped: {skipped}  missing: {missing}")
        return 0
    
    except FileNotFoundError as e:
        logger.error(f"Manifest file not found: {e}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in manifest: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
