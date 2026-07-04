#!/usr/bin/env python3
"""Generate default playbooks for MITRE ATT&CK Enterprise groups.

The generator is intentionally deterministic: it fetches the public MITRE
Enterprise ATT&CK STIX bundle, creates one default library playbook per
intrusion-set/group (Gxxxx), and appends only missing entries to the manifest.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import textwrap
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import date
from pathlib import Path

# ── Setup logging for visibility ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROOT = ROOT / "app" / "playbooks-main"
GROUP_DIR = PLAYBOOK_ROOT / "threat-groups"
MANIFEST_PATH = PLAYBOOK_ROOT / "manifest.json"

TACTIC_PRIORITY = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_LABELS = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def fetch_enterprise_attack() -> dict:
    """Fetch MITRE Enterprise ATT&CK STIX bundle with error handling."""
    try:
        logger.info(f"Fetching MITRE ATT&CK STIX from {ATTACK_URL}...")
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


def slugify(value: str) -> str:
    value = value.lower().replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:80] or "mitre-group"


def external_ref(obj: dict, prefix: str) -> dict | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith(prefix):
            return ref
    return None


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    value = re.sub(r"\(Citation:[^)]+\)", "", value)
    return re.sub(r"\s+", " ", value).strip()


def tactic_sort_key(tactic: str) -> tuple[int, str]:
    try:
        return (TACTIC_PRIORITY.index(tactic), tactic)
    except ValueError:
        return (len(TACTIC_PRIORITY), tactic)


def build_indexes(bundle: dict) -> tuple[list[dict], dict[str, dict], dict[str, list[dict]]]:
    techniques_by_stix: dict[str, dict] = {}
    groups: list[dict] = []
    uses_by_group: dict[str, list[dict]] = defaultdict(list)

    for obj in bundle["objects"]:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "attack-pattern":
            ref = external_ref(obj, "T")
            if not ref:
                continue
            tactics = [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            techniques_by_stix[obj["id"]] = {
                "id": ref["external_id"],
                "name": obj.get("name", ""),
                "url": ref.get("url", ""),
                "tactics": sorted(set(tactics), key=tactic_sort_key),
            }
        elif obj.get("type") == "intrusion-set":
            ref = external_ref(obj, "G")
            if ref:
                groups.append({**obj, "mitre_id": ref["external_id"], "url": ref.get("url", "")})

    for obj in bundle["objects"]:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique = techniques_by_stix.get(obj.get("target_ref"))
        if technique:
            uses_by_group[obj["source_ref"]].append(
                {
                    **technique,
                    "relationship": clean_text(obj.get("description")),
                }
            )

    groups.sort(key=lambda item: item["mitre_id"])
    return groups, techniques_by_stix, uses_by_group


def technique_summary(techniques: list[dict], limit: int = 12) -> str:
    if not techniques:
        return "No ATT&CK techniques are currently mapped in MITRE CTI for this group."
    selected = techniques[:limit]
    rendered = ", ".join(f"{tech['id']} {tech['name']}" for tech in selected)
    remaining = len(techniques) - len(selected)
    if remaining > 0:
        rendered += f", plus {remaining} additional mapped technique(s)"
    return rendered


def tactic_summary(techniques: list[dict]) -> str:
    tactics = sorted({t for tech in techniques for t in tech.get("tactics", [])}, key=tactic_sort_key)
    if not tactics:
        return "No explicit tactics mapped"
    return ", ".join(TACTIC_LABELS.get(t, t.replace("-", " ").title()) for t in tactics)


def build_detection_steps(group: dict, techniques: list[dict]) -> list[dict]:  # noqa: keep signature for reference
    """Build minimal investigation steps from STIX context - no hardcoded queries."""
    group_name = group["name"]
    group_id   = group["mitre_id"]
    aliases    = ", ".join(group.get("aliases", [])[:12]) or "No public aliases listed"
    tactics    = tactic_summary(techniques)
    top_techs  = technique_summary(techniques)
    mitre_url  = group.get("url") or f"https://attack.mitre.org/groups/{group_id}/"

    return [
        {
            "n": 1,
            "title": f"Profile {group_name} with MITRE ATT&CK context",
            "detail": (
                f"MITRE Group ID: {group_id}. Aliases: {aliases}. Primary tactics: {tactics}. "
                f"Techniques: {top_techs}. Reference: {mitre_url}."
            ),
            "queries": {},
        },
        {
            "n": 2,
            "title": "Hunt initial access, execution, and persistence behaviors",
            "detail": (
                "Search for public-facing exploitation, suspicious script execution, LOLBins, web shells, "
                "scheduled tasks, service creation, and autorun registry changes attributed to this group's technique set."
            ),
            "queries": {},
        },
        {
            "n": 3,
            "title": "Hunt credential access, discovery, and lateral movement",
            "detail": (
                "Investigate LSASS access, domain enumeration, network discovery, RDP/SMB/WinRM lateral movement, "
                "and authentication anomalies consistent with this group's mapped techniques."
            ),
            "queries": {},
        },
        {
            "n": 4,
            "title": "Hunt command-and-control and exfiltration",
            "detail": (
                "Monitor for C2 beaconing patterns, DNS tunneling, high-entropy DNS queries, suspicious HTTP POST "
                "activity, and large outbound transfers matching this group's known tradecraft."
            ),
            "queries": {},
        },
    ]


def build_playbook(group: dict, techniques: list[dict], num: int) -> dict:
    group_id = group["mitre_id"]
    group_name = group.get("name") or group_id
    aliases = group.get("aliases", [])
    mitre_ids = [tech["id"] for tech in techniques[:24]]
    description = clean_text(group.get("description"))
    if not description:
        description = f"{group_name} is a MITRE ATT&CK Enterprise intrusion-set/group ({group_id})."

    return {
        "id": f"apt-{group_id.lower()}",
        "num": num,
        "name": f"Group - {group_name}",
        "fullName": f"{group_name} ({group_id}) Threat Group Hunt",
        "type": "Threat Group / APT Hunt",
        "severity": "Critical",
        "priority": "High",
        "detection": "Security Onion, Sysmon, OSQuery, Velociraptor, Elastic, Carbon Black",
        "scenario": (
            f"{description} This default playbook uses MITRE ATT&CK mapped techniques and practical "
            "Security Onion, Sysmon, OSQuery, Velociraptor, Elastic, and Carbon Black hunts to investigate "
            f"activity consistent with {group_name}."
        ),
        "mitre": ", ".join(mitre_ids),
        "aliases": aliases,
        "mitreGroupId": group_id,
        "mitreUrl": group.get("url") or f"https://attack.mitre.org/groups/{group_id}/",
        "tools": "Security Onion; Sysmon; OSQuery; Velociraptor; Elastic; Carbon Black",
        "sev": "critical",
        "cat": "Threat Groups",
        "source": "library",
        "updated": date.today().isoformat(),
        "detSteps": build_detection_steps(group, techniques),
        "contSteps": [
            {
                "title": "Contain affected hosts and identities",
                "detail": "Isolate confirmed compromised endpoints, disable impacted accounts, revoke active sessions/tokens, and block observed C2 destinations while preserving evidence.",
                "queries": {},
            },
            {
                "title": "Apply tactical network controls",
                "detail": "Block confirmed malicious infrastructure, restrict administrative protocols to jump boxes, and increase Security Onion alert visibility for the relevant MITRE techniques.",
                "queries": {},
            },
        ],
        "eradSteps": [
            {
                "title": "Remove persistence and actor tooling",
                "detail": "Remove malicious services, scheduled tasks, startup items, web shells, unauthorized accounts, and binaries identified during the hunt. Validate with Sysmon/OSQuery/Velociraptor before reconnecting hosts.",
                "queries": {},
            },
            {
                "title": "Patch exploited weaknesses",
                "detail": "Patch exploited public-facing applications, harden identity controls, rotate exposed credentials, and remediate vulnerable software or appliance firmware relevant to the observed technique set.",
                "queries": {},
            },
        ],
        "recSteps": [
            {
                "title": "Restore and monitor",
                "detail": "Restore systems from trusted backups where needed, re-enable network access in stages, and monitor Security Onion dashboards for recurrence of mapped techniques for at least two business cycles.",
                "queries": {},
            },
            {
                "title": "Improve ATT&CK coverage",
                "detail": "Update detection engineering backlog with uncovered ATT&CK techniques, tune noisy queries with environment-specific allowlists, and document lessons learned in the incident record.",
                "queries": {},
            },
        ],
    }


def main() -> int:
    """Generate MITRE group playbooks with comprehensive error handling."""
    try:
        logger.info("Starting MITRE group playbook generation...")
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        existing_ids = {item["id"] for item in manifest.get("playbooks", [])}
        existing_files = {item["file"] for item in manifest.get("playbooks", [])}
        max_num = max((int(item.get("num", 0)) for item in manifest.get("playbooks", [])), default=0)

        bundle = fetch_enterprise_attack()
        groups, _techniques_by_stix, uses_by_group = build_indexes(bundle)
        GROUP_DIR.mkdir(parents=True, exist_ok=True)

        added = 0
        for group in groups:
            group_id = group["mitre_id"]
            playbook_id = f"apt-{group_id.lower()}"
            rel_file = f"threat-groups/{playbook_id}-{slugify(group.get('name', group_id))}.json"
            # Skip only when the entry already exists AND the file is present on disk.
            # Regenerate if the file is missing (e.g. fresh build from committed manifest).
            file_exists = (PLAYBOOK_ROOT / rel_file).exists()
            if (playbook_id in existing_ids or rel_file in existing_files) and file_exists:
                continue

            techniques = sorted(
                uses_by_group.get(group["id"], []),
                key=lambda tech: (
                    min((tactic_sort_key(t) for t in tech.get("tactics", [])), default=(99, "")),
                    tech["id"],
                ),
            )
            max_num += 1
            playbook = build_playbook(group, techniques, max_num)
            (PLAYBOOK_ROOT / rel_file).write_text(
                json.dumps(playbook, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            new_entry = {
                    "id": playbook_id,
                    "num": max_num,
                    "name": playbook["name"],
                    "cat": "Threat Groups",
                    "sev": "critical",
                    "type": "Threat Group / APT Hunt",
                    "mitre": playbook["mitre"],
                    "source": "library",
                    "file": rel_file,
                    "related": [],
                    "tools": [],
                }
            # Upsert: replace existing entry or append new one
            existing_idx = next(
                (i for i, p in enumerate(manifest["playbooks"]) if p.get("id") == playbook_id),
                None,
            )
            if existing_idx is not None:
                manifest["playbooks"][existing_idx] = new_entry
            else:
                manifest["playbooks"].append(new_entry)
            added += 1

        manifest["generated"] = date.today().isoformat()
        MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        logger.info(f"MITRE Enterprise groups processed: {len(groups)}")
        logger.info(f"New default group playbooks added: {added}")
        logger.info(f"Manifest total playbooks: {len(manifest['playbooks'])}")
        return 0
    
    except FileNotFoundError as e:
        logger.error(f"Required file not found: {e}")
        return 1
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in manifest: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
