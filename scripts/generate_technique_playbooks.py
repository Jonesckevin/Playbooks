#!/usr/bin/env python3
"""Generate MITRE Enterprise ATT&CK technique playbooks from live STIX data.

Fetches the Enterprise ATT&CK STIX bundle at Docker build time.
Produces one playbook per technique with STIX metadata and empty detection stubs.
No hardcoded queries - add detection content via custom override files in app/playbooks-custom/.

Also generates app/playbooks-main/mitre-index.json (slim technique lookup for the navigator).

Usage: python scripts/generate_technique_playbooks.py
"""
from __future__ import annotations

import json
import logging
import re
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

# ── Setup logging for visibility ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data"
    "/master/enterprise-attack/enterprise-attack.json"
)
ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_MAIN = ROOT / "app" / "playbooks-main"
OUT_DIR = PLAYBOOK_MAIN / "techniques"
MANIFEST_PATH = PLAYBOOK_MAIN / "manifest.json"
MITRE_INDEX_PATH = PLAYBOOK_MAIN / "mitre-index.json"
TODAY = date.today().isoformat()

# Kill-chain tactic order (matches ATT&CK navigator layer ordering)
TACTIC_PRIORITY = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
    "impair-process-control", "inhibit-response-function", "evasion",
    "network-effects", "remote-service-effects",
]

TACTIC_IDS: dict[str, str] = {
    "reconnaissance":          "TA0043",
    "resource-development":    "TA0042",
    "initial-access":          "TA0001",
    "execution":               "TA0002",
    "persistence":             "TA0003",
    "privilege-escalation":    "TA0004",
    "defense-evasion":         "TA0005",
    "credential-access":       "TA0006",
    "discovery":               "TA0007",
    "lateral-movement":        "TA0008",
    "collection":              "TA0009",
    "command-and-control":     "TA0011",
    "exfiltration":            "TA0010",
    "impact":                  "TA0040",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def tactic_sort_key(slug: str) -> int:
    try:
        return TACTIC_PRIORITY.index(slug)
    except ValueError:
        return len(TACTIC_PRIORITY)


def tactic_label(slug: str) -> str:
    return slug.replace("-", " ").title()


def slugify(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower())
    return value.strip("-")[:80]


def clean(text: str | None) -> str:
    if not text:
        return ""
    text = re.sub(r"\(Citation:[^)]+\)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def external_ref(obj: dict, prefix: str) -> dict | None:
    for ref in obj.get("external_references", []):
        if (
            ref.get("source_name") == "mitre-attack"
            and ref.get("external_id", "").startswith(prefix)
        ):
            return ref
    return None


# ── Fetch & parse ──────────────────────────────────────────────────────────────

def fetch_stix() -> dict:
    """Fetch MITRE STIX bundle with error handling."""
    try:
        logger.info(f"Fetching STIX from {ATTACK_URL}...")
        with urllib.request.urlopen(ATTACK_URL, timeout=120) as response:
            bundle = json.load(response)
            logger.info(f"✓ Successfully fetched STIX bundle ({len(bundle.get('objects', []))} objects)")
            return bundle
    except urllib.error.URLError as e:
        logger.error(f"Network error fetching MITRE STIX: {e}")
        logger.error("Tip: Check internet connectivity or MITRE server status")
        raise SystemExit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in MITRE STIX response: {e}")
        raise SystemExit(1)
    except Exception as e:
        logger.error(f"Unexpected error fetching MITRE STIX: {e}")
        raise SystemExit(1)


def parse_techniques(bundle: dict) -> list[dict]:
    """Extract all non-revoked, non-deprecated techniques from the STIX bundle."""
    techniques: list[dict] = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = external_ref(obj, "T")
        if not ref:
            continue

        tid = ref["external_id"]
        tactics = sorted(
            {
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            },
            key=tactic_sort_key,
        )
        domains = [
            d.replace("-attack", "")
            for d in obj.get("x_mitre_domains", ["enterprise-attack"])
        ]
        data_sources = [
            (ds.get("name", ds) if isinstance(ds, dict) else ds)
            for ds in obj.get("x_mitre_data_sources", [])
        ]

        techniques.append({
            "id":             tid,
            "name":           obj.get("name", tid),
            "description":    clean(obj.get("description", "")),
            "detection":      clean(obj.get("x_mitre_detection", "")),
            "url":            ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
            "tactics":        tactics,
            "platforms":      obj.get("x_mitre_platforms", []),
            "dataSources":    data_sources,
            "isSubtechnique": obj.get("x_mitre_is_subtechnique", False),
            "domains":        domains,
        })

    # Sort by base technique ID then sub-technique numerically
    techniques.sort(key=lambda t: (t["id"].split(".")[0], t["id"]))
    return techniques


# ── Build output artefacts ────────────────────────────────────────────────────

def build_playbook(tech: dict) -> dict:
    """Produce a minimal playbook JSON for a single technique.

    Detection content is intentionally empty - add via custom override files
    in app/playbooks-custom/ mirroring the playbooks-main/ structure.
    """
    tid    = tech["id"]
    name   = tech["name"]
    tactic = tech["tactics"][0] if tech["tactics"] else "other"
    det_detail = (
        tech["detection"]
        or tech["description"]
        or f"Refer to MITRE ATT&CK {tid} for detection guidance: {tech['url']}"
    )

    return {
        "id":             f"tech-{tid.lower()}",
        "name":           f"{tid} \u2013 {name}",
        "type":           "Enterprise ATT&CK Technique",
        "severity":       "high",
        "cat":            "Techniques",
        "tactic":         tactic,
        "tacticLabel":    tactic_label(tactic),
        "tacticId":       TACTIC_IDS.get(tactic, ""),
        "domain":         "enterprise",
        "isSubtechnique": tech["isSubtechnique"],
        "mitre":          [tid],
        "mitreUrl":       tech["url"],
        "platforms":      tech["platforms"],
        "dataSources":    tech["dataSources"],
        "source":         "library-override",
        "updated":        TODAY,
        "scenario": (
            tech["description"][:500] if tech["description"]
            else f"{name} ({tid}) - see {tech['url']}"
        ),
        "investigation": {
            "detectionAnalysis": [
                {
                    "n": 1,
                    "title": f"Detect {name} ({tid})",
                    "detail": det_detail,
                    "queries": {},
                }
            ],
            "containment": [
                {
                    "n": 1,
                    "title": "Contain affected systems",
                    "detail": "Isolate impacted hosts and revoke compromised credentials.",
                    "queries": {},
                }
            ],
            "eradication": [
                {
                    "n": 1,
                    "title": "Remove malicious artifacts",
                    "detail": "Remove persistence mechanisms and malicious tooling identified during investigation.",
                    "queries": {},
                }
            ],
            "recovery": [
                {
                    "n": 1,
                    "title": "Restore and harden",
                    "detail": "Restore from clean backups, apply patches, and tune detection rules.",
                    "queries": {},
                }
            ],
        },
    }


def write_mitre_index(techniques: list[dict]) -> None:
    """Write a slim mitre-index.json used by the frontend navigator."""
    index = [
        {"id": t["id"], "name": t["name"], "url": t["url"], "domains": t["domains"]}
        for t in techniques
    ]
    MITRE_INDEX_PATH.write_text(
        json.dumps({"techniques": index}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote mitre-index.json ({len(index)} entries)")


def main() -> int:
    try:
        logger.info("Starting MITRE technique playbook generation...")
        bundle = fetch_stix()
        techniques = parse_techniques(bundle)
        logger.info(f"Found {len(techniques)} techniques")

        PLAYBOOK_MAIN.mkdir(parents=True, exist_ok=True)
        write_mitre_index(techniques)

        generated = 0
        errors = 0
        manifest_entries: list[dict] = []

        for tech in techniques:
            try:
                tid    = tech["id"]
                tactic = tech["tactics"][0] if tech["tactics"] else "other"
                tactic_dir = OUT_DIR / tactic
                tactic_dir.mkdir(parents=True, exist_ok=True)

                name_slug = slugify(tech["name"])
                filename  = f"tech-{tid.lower()}-{name_slug}.json"
                out_file  = tactic_dir / filename

                pb = build_playbook(tech)
                out_file.write_text(
                    json.dumps(pb, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                generated += 1

                manifest_entries.append({
                    "id":             f"tech-{tid.lower()}",
                    "num":            10000 + generated,
                    "name":           f"{tid} – {clean(tech['name'])}",
                    "cat":            "Techniques",
                    "tactic":         tactic,
                    "tacticId":       TACTIC_IDS.get(tactic, ""),
                    "tacticLabel":    tactic_label(tactic),
                    "domain":         "enterprise",
                    "sev":            "high",
                    "type":           "Enterprise ATT&CK Technique",
                    "mitre":          tid,
                    "isSubtechnique": tech["isSubtechnique"],
                    "source":         "library-override",
                    "file":           f"techniques/{tactic}/{filename}",
                    "tools":          [],
                })

                if generated % 100 == 0:
                    logger.info(f"Generated {generated} playbooks...")

            except Exception as exc:
                logger.error(f"ERROR {tech.get('id', '?')}: {exc}")
                errors += 1

        # Merge with existing manifest (preserve non-technique entries)
        if MANIFEST_PATH.exists():
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            manifest["playbooks"] = [
                p for p in manifest.get("playbooks", [])
                if not str(p.get("id", "")).startswith("tech-")
            ]
            manifest["playbooks"].extend(manifest_entries)
            manifest["generated"] = TODAY
            MANIFEST_PATH.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

        logger.info(f"Technique playbooks generated: {generated}")
        logger.info(f"Errors: {errors}")
        logger.info(f"Output: {OUT_DIR}")
        return 0 if errors == 0 else 1
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in manifest: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
