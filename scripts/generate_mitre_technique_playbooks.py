#!/usr/bin/env python3
"""Generate MITRE ATT&CK technique playbooks for Enterprise, Mobile, and ICS domains.

Each technique gets its own playbook JSON file with:
  - Description and detection guidance from the STIX bundle
  - Data-source-driven detection queries for Security Onion, Sysmon, OSQuery,
    Velociraptor, Elastic, Carbon Black, and a generated Sigma YAML rule
  - Organized under playbooks/techniques/{tactic-slug}/

Usage:
    python scripts/generate_mitre_technique_playbooks.py [--force]

Options:
    --force   Overwrite existing playbook JSON files (manifest entries are never duplicated)
"""

from __future__ import annotations

import io
import json
import re
import sys
import textwrap
import urllib.request
import uuid
from collections import defaultdict
from datetime import date
from pathlib import Path

# Ensure UTF-8 output on Windows (avoids charmap encoding errors)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Configuration ────────────────────────────────────────────────────────────

DOMAINS: dict[str, dict] = {
    "enterprise": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "label": "Enterprise ATT&CK",
    },
    "mobile": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
        "label": "Mobile ATT&CK",
    },
    "ics": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
        "label": "ICS ATT&CK",
    },
}

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROOT = ROOT / "app" / "playbooks"
TECH_DIR = PLAYBOOK_ROOT / "techniques"
MANIFEST_PATH = PLAYBOOK_ROOT / "manifest.json"

# Technique playbook IDs start at this base to avoid collision with library/group playbooks
TECH_NUM_BASE = 10000

# Kill-chain ordered tactic slugs (Enterprise). Mobile/ICS order determined from STIX.
ENTERPRISE_TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
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

# Severity by primary tactic
TACTIC_SEVERITY: dict[str, str] = {
    "reconnaissance": "low",
    "resource-development": "low",
    "initial-access": "high",
    "execution": "high",
    "persistence": "high",
    "privilege-escalation": "critical",
    "defense-evasion": "medium",
    "credential-access": "critical",
    "discovery": "medium",
    "lateral-movement": "high",
    "collection": "high",
    "command-and-control": "high",
    "exfiltration": "critical",
    "impact": "critical",
    # ICS
    "impair-process-control": "critical",
    "inhibit-response-function": "critical",
    "evasion": "medium",
    # Mobile
    "network-effects": "high",
    "remote-service-effects": "high",
}

# ── Data-source → query-fragment mapping ────────────────────────────────────
# Keys match STIX x_mitre_data_sources subcategory strings.
# "so_kql"      → Security Onion / Kibana KQL fragment
# "elastic"     → Elastic KQL/EQL fragment
# "sysmon_evt"  → Sysmon XML EventFiltering element name
# "sysmon_code" → Windows Event ID (for Security/WinEventLog reference)
# "osquery_tbl" → Primary osquery table(s)
# "vql_source"  → Velociraptor VQL table function

DS_MAP: dict[str, dict] = {
    "Process: Process Creation": {
        "so_kql": "(event.module:sysmon AND event.code:1) OR (event.category:process AND event.type:start)",
        "elastic": 'event.category:"process" and event.type:"start"',
        "sysmon_evt": "ProcessCreate",
        "sysmon_code": "1",
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Process: Process Access": {
        "so_kql": "(event.module:sysmon AND event.code:10)",
        "elastic": 'event.category:"process" and event.type:"access"',
        "sysmon_evt": "ProcessAccess",
        "sysmon_code": "10",
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Process: OS API Execution": {
        "so_kql": "(event.module:sysmon AND event.code:1)",
        "elastic": 'event.category:"process"',
        "sysmon_evt": "ProcessCreate",
        "sysmon_code": "1",
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Process: Process Termination": {
        "so_kql": "(event.module:sysmon AND event.code:5)",
        "elastic": 'event.category:"process" and event.type:"end"',
        "sysmon_evt": "ProcessTerminate",
        "sysmon_code": "5",
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Network Traffic: Network Connection Creation": {
        "so_kql": "(event.module:sysmon AND event.code:3) OR event.dataset:zeek.conn",
        "elastic": 'event.category:"network" and event.type:"connection"',
        "sysmon_evt": "NetworkConnect",
        "sysmon_code": "3",
        "osquery_tbl": "process_open_sockets",
        "vql_source": "netstat()",
    },
    "Network Traffic: Network Traffic Content": {
        "so_kql": "(event.dataset:zeek.http OR event.dataset:zeek.ssl OR event.dataset:zeek.dns)",
        "elastic": 'event.category:"network"',
        "sysmon_evt": "NetworkConnect",
        "sysmon_code": "3",
        "osquery_tbl": "process_open_sockets",
        "vql_source": "netstat()",
    },
    "Network Traffic: Network Traffic Flow": {
        "so_kql": "event.dataset:zeek.conn",
        "elastic": 'event.category:"network"',
        "sysmon_evt": "NetworkConnect",
        "sysmon_code": "3",
        "osquery_tbl": "process_open_sockets",
        "vql_source": "netstat()",
    },
    "File: File Creation": {
        "so_kql": "(event.module:sysmon AND event.code:11)",
        "elastic": 'event.category:"file" and event.type:"creation"',
        "sysmon_evt": "FileCreate",
        "sysmon_code": "11",
        "osquery_tbl": "file",
        "vql_source": "glob()",
    },
    "File: File Modification": {
        "so_kql": "(event.module:sysmon AND event.code:(11 OR 23))",
        "elastic": 'event.category:"file" and event.type:"change"',
        "sysmon_evt": "FileCreate",
        "sysmon_code": "11",
        "osquery_tbl": "file",
        "vql_source": "glob()",
    },
    "File: File Access": {
        "so_kql": "(event.module:sysmon AND event.code:(11 OR 23))",
        "elastic": 'event.category:"file" and event.type:"access"',
        "sysmon_evt": "FileCreate",
        "sysmon_code": "11",
        "osquery_tbl": "file",
        "vql_source": "glob()",
    },
    "File: File Deletion": {
        "so_kql": "(event.module:sysmon AND event.code:23)",
        "elastic": 'event.category:"file" and event.type:"deletion"',
        "sysmon_evt": "FileDelete",
        "sysmon_code": "23",
        "osquery_tbl": "file",
        "vql_source": "glob()",
    },
    "File: File Metadata": {
        "so_kql": "(event.module:sysmon AND event.code:11)",
        "elastic": 'event.category:"file"',
        "sysmon_evt": "FileCreate",
        "sysmon_code": "11",
        "osquery_tbl": "file",
        "vql_source": "glob()",
    },
    "Windows Registry: Windows Registry Key Creation": {
        "so_kql": "(event.module:sysmon AND event.code:12)",
        "elastic": 'event.category:"registry" and event.type:"creation"',
        "sysmon_evt": "RegistryEvent",
        "sysmon_code": "12",
        "osquery_tbl": "registry",
        "vql_source": "read_reg_mru()",
    },
    "Windows Registry: Windows Registry Key Modification": {
        "so_kql": "(event.module:sysmon AND event.code:(12 OR 13 OR 14))",
        "elastic": 'event.category:"registry" and event.type:"change"',
        "sysmon_evt": "RegistryEvent",
        "sysmon_code": "13",
        "osquery_tbl": "registry",
        "vql_source": "read_reg_mru()",
    },
    "Windows Registry: Windows Registry Key Deletion": {
        "so_kql": "(event.module:sysmon AND event.code:12)",
        "elastic": 'event.category:"registry" and event.type:"deletion"',
        "sysmon_evt": "RegistryEvent",
        "sysmon_code": "12",
        "osquery_tbl": "registry",
        "vql_source": "read_reg_mru()",
    },
    "Command: Command Execution": {
        "so_kql": "(event.module:sysmon AND event.code:1) OR (event.code:4103 AND event.provider:Microsoft-Windows-PowerShell)",
        "elastic": 'event.category:"process" and event.type:"start"',
        "sysmon_evt": "ProcessCreate",
        "sysmon_code": "1",
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Script: Script Execution": {
        "so_kql": "(event.code:4104 AND event.provider:Microsoft-Windows-PowerShell) OR (event.module:sysmon AND event.code:1)",
        "elastic": 'event.category:"process"',
        "sysmon_evt": "ProcessCreate",
        "sysmon_code": "4104",
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "User Account: User Account Authentication": {
        "so_kql": "(event.code:(4624 OR 4625 OR 4648) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"authentication"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "logged_in_users",
        "vql_source": "users()",
    },
    "User Account: User Account Creation": {
        "so_kql": "(event.code:(4720 OR 4732) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"iam" and event.type:"user"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "users",
        "vql_source": "users()",
    },
    "User Account: User Account Modification": {
        "so_kql": "(event.code:(4738 OR 4735 OR 4737) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"iam"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "users",
        "vql_source": "users()",
    },
    "User Account: User Account Deletion": {
        "so_kql": "(event.code:(4726 OR 4733) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"iam" and event.type:"deletion"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "users",
        "vql_source": "users()",
    },
    "Logon Session: Logon Session Creation": {
        "so_kql": "(event.code:(4624 OR 4625 OR 4648) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"authentication" and event.outcome:"success"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "logged_in_users",
        "vql_source": "users()",
    },
    "Logon Session: Logon Session Metadata": {
        "so_kql": "(event.code:4624 AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"authentication"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "logged_in_users",
        "vql_source": "users()",
    },
    "Service: Service Creation": {
        "so_kql": "(event.code:7045 AND event.provider:\"Service Control Manager\")",
        "elastic": 'event.category:"process"',
        "sysmon_evt": None,
        "sysmon_code": "7045",
        "osquery_tbl": "services",
        "vql_source": "services()",
    },
    "Service: Service Modification": {
        "so_kql": "(event.code:7040 AND event.provider:\"Service Control Manager\")",
        "elastic": 'event.category:"configuration"',
        "sysmon_evt": None,
        "sysmon_code": "7040",
        "osquery_tbl": "services",
        "vql_source": "services()",
    },
    "Scheduled Job: Scheduled Job Creation": {
        "so_kql": "(event.code:4698 AND event.provider:Microsoft-Windows-TaskScheduler)",
        "elastic": 'event.category:"process"',
        "sysmon_evt": None,
        "sysmon_code": "4698",
        "osquery_tbl": "scheduled_tasks",
        "vql_source": "ScheduledTasks()",
    },
    "Scheduled Job: Scheduled Job Modification": {
        "so_kql": "(event.code:(4698 OR 4702) AND event.provider:Microsoft-Windows-TaskScheduler)",
        "elastic": 'event.category:"process"',
        "sysmon_evt": None,
        "sysmon_code": "4702",
        "osquery_tbl": "scheduled_tasks",
        "vql_source": "ScheduledTasks()",
    },
    "Driver: Driver Load": {
        "so_kql": "(event.module:sysmon AND event.code:6)",
        "elastic": 'event.category:"driver"',
        "sysmon_evt": "DriverLoad",
        "sysmon_code": "6",
        "osquery_tbl": "kernel_extensions",
        "vql_source": "modules()",
    },
    "Module: Module Load": {
        "so_kql": "(event.module:sysmon AND event.code:7)",
        "elastic": 'event.category:"library"',
        "sysmon_evt": "ImageLoad",
        "sysmon_code": "7",
        "osquery_tbl": "process_memory_map",
        "vql_source": "modules()",
    },
    "Named Pipe: Named Pipe Metadata": {
        "so_kql": "(event.module:sysmon AND event.code:(17 OR 18))",
        "elastic": 'event.category:"process"',
        "sysmon_evt": "PipeEvent",
        "sysmon_code": "17",
        "osquery_tbl": "pipes",
        "vql_source": "pipes()",
    },
    "WMI: WMI Creation": {
        "so_kql": "(event.module:sysmon AND event.code:(19 OR 20 OR 21))",
        "elastic": 'event.category:"process"',
        "sysmon_evt": "WmiEvent",
        "sysmon_code": "19",
        "osquery_tbl": "wmi_event_filters",
        "vql_source": "wmi_event_filters()",
    },
    "Active Directory: Active Directory Object Access": {
        "so_kql": "(event.code:(4661 OR 4662 OR 4663) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"iam"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "groups",
        "vql_source": "users()",
    },
    "Active Directory: Active Directory Credential Request": {
        "so_kql": "(event.code:(4768 OR 4769 OR 4770 OR 4771) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"authentication"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "logged_in_users",
        "vql_source": "users()",
    },
    "Active Directory: Active Directory Object Creation": {
        "so_kql": "(event.code:(4741 OR 4743 OR 4720) AND event.provider:Microsoft-Windows-Security-Auditing)",
        "elastic": 'event.category:"iam"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "groups",
        "vql_source": "users()",
    },
    "Application Log: Application Log Content": {
        "so_kql": "event.kind:event AND event.category:authentication",
        "elastic": 'event.kind:"event"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "system_info",
        "vql_source": "info()",
    },
    "Cloud Service: Cloud Service Enumeration": {
        "so_kql": "(event.dataset:(aws.cloudtrail OR azure.activitylogs OR gcp.audit))",
        "elastic": 'event.category:"configuration"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Cloud Service: Cloud Service Modification": {
        "so_kql": "(event.dataset:(aws.cloudtrail OR azure.activitylogs OR gcp.audit))",
        "elastic": 'event.category:"configuration"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Cloud Storage: Cloud Storage Access": {
        "so_kql": "(event.dataset:(aws.cloudtrail OR azure.activitylogs OR gcp.audit))",
        "elastic": 'event.category:"database"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Cloud Storage: Cloud Storage Metadata": {
        "so_kql": "(event.dataset:(aws.cloudtrail OR azure.activitylogs OR gcp.audit))",
        "elastic": 'event.category:"database"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
    "Firmware: Firmware Modification": {
        "so_kql": "event.kind:event AND event.category:host",
        "elastic": 'event.category:"configuration"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "system_info",
        "vql_source": "info()",
    },
    "Sensor Health: Host Status": {
        "so_kql": "event.kind:metric",
        "elastic": 'event.category:"host"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "system_info",
        "vql_source": "info()",
    },
    "Container: Container Start": {
        "so_kql": "(event.category:process AND event.dataset:docker OR event.dataset:kubernetes.audit)",
        "elastic": 'event.category:"process"',
        "sysmon_evt": "ProcessCreate",
        "sysmon_code": "1",
        "osquery_tbl": "docker_containers",
        "vql_source": "pslist()",
    },
    "Malware Repository: Malware Metadata": {
        "so_kql": "event.dataset:suricata.eve AND event.kind:alert",
        "elastic": 'event.category:"threat"',
        "sysmon_evt": None,
        "sysmon_code": None,
        "osquery_tbl": "processes",
        "vql_source": "pslist()",
    },
}

# Fallback for unknown data sources
DS_FALLBACK: dict = {
    "so_kql": "(event.kind:event AND event.category:(process OR network OR file))",
    "elastic": 'event.kind:"event"',
    "sysmon_evt": "ProcessCreate",
    "sysmon_code": "1",
    "osquery_tbl": "processes",
    "vql_source": "pslist()",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def fetch_bundle(url: str) -> dict:
    print(f"  Fetching {url} …")
    with urllib.request.urlopen(url, timeout=180) as r:  # noqa: S310
        return json.load(r)


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    value = re.sub(r"\(Citation:[^)]+\)", "", value)
    return re.sub(r"\s+", " ", value).strip()


def slugify(value: str) -> str:
    value = str(value).lower().replace("&", " and ")
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")[:80] or "unknown"


def external_ref(obj: dict, prefix: str) -> dict | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and str(ref.get("external_id", "")).startswith(prefix):
            return ref
    return None


def tactic_sort_key(slug: str, tactic_order: list[str]) -> tuple[int, str]:
    try:
        return (tactic_order.index(slug), slug)
    except ValueError:
        return (len(tactic_order), slug)


def extract_exe_names(text: str) -> list[str]:
    """Extract .exe names mentioned in technique text for query hints."""
    found = re.findall(r"[\w.]+\.exe", text, re.IGNORECASE)
    normalized = list({f.lower() for f in found if f.lower() not in {"example.exe", "binary.exe"}})
    return sorted(normalized)[:6]


def extract_ports(text: str) -> list[str]:
    """Extract port numbers from technique text."""
    found = re.findall(r"\bport[s]?\s+(\d{1,5})\b|\b(\d{1,5})\s+(?:tcp|udp|port)\b", text, re.IGNORECASE)
    ports = []
    for match in found:
        for p in match:
            if p and 0 < int(p) < 65536:
                ports.append(p)
    return list(dict.fromkeys(ports))[:6]


# ── Query Generation ─────────────────────────────────────────────────────────

def _get_ds_info(data_sources: list[str]) -> dict:
    """Pick the best matching DS_MAP entry for a technique's data_sources list.

    Uses a priority order so that the most informative/specific data source is
    chosen first.  Handles both old-style 'Category: Component' strings (STIX
    v9) and new-style bare component names (ATT&CK v14+ x-mitre-data-component).
    """
    # Priority: prefer more specific/actionable event types first
    DS_PRIORITY_COMPONENTS = [
        "Process Access",           # Sysmon Event 10 – best for memory access attacks
        "Process Creation",         # Sysmon Event 1 – fundamental process telemetry
        "Network Connection Creation",
        "Network Traffic Content",
        "Network Traffic Flow",
        "Windows Registry Key Modification",
        "Windows Registry Key Creation",
        "Windows Registry Key Deletion",
        "File Creation",
        "File Modification",
        "File Deletion",
        "Command Execution",
        "Script Execution",
        "WMI Creation",
        "Driver Load",
        "Module Load",
        "Named Pipe Metadata",
        "Logon Session Creation",
        "User Account Authentication",
        "User Account Creation",
        "Service Creation",
        "Scheduled Job Creation",
    ]

    def component_priority(ds_name: str) -> int:
        # Extract bare component (strip "Category: " prefix if present)
        comp = ds_name.split(": ", 1)[-1] if ": " in ds_name else ds_name
        try:
            return DS_PRIORITY_COMPONENTS.index(comp)
        except ValueError:
            return len(DS_PRIORITY_COMPONENTS)

    # Sort data sources by priority so we pick the best one first
    ordered = sorted(data_sources, key=component_priority)

    for ds in ordered:
        # Exact match (old-style: "Category: Component")
        if ds in DS_MAP:
            return DS_MAP[ds]
        # New-style bare component name – try suffix match against DS_MAP keys
        for key, val in DS_MAP.items():
            comp_part = key.split(": ", 1)[-1] if ": " in key else key
            if comp_part.lower() == ds.lower():
                return val
    for ds in ordered:
        # Partial prefix match on category
        cat = ds.split(":")[0].strip() if ":" in ds else ds
        for key, val in DS_MAP.items():
            if key.startswith(cat + ":"):
                return val
    return DS_FALLBACK


def build_security_onion_query(tech: dict, ds_info: dict) -> str:
    tid = tech["id"]
    name = tech["name"]
    tactic = tech.get("primary_tactic", "")
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))
    ports = extract_ports(tech.get("description", "") + " " + tech.get("detection", ""))

    lines = [f"# Security Onion KQL – {name} ({tid})"]
    lines.append(f"# MITRE ATT&CK: {tid} | Tactic: {tactic}")
    lines.append(f"# Ref: {tech.get('url', '')}")
    lines.append("")
    # Primary data-source fragment
    so_frag = ds_info.get("so_kql", DS_FALLBACK["so_kql"])
    lines.append(f"({so_frag})")
    # Technique ID pivot (works when SIEM maps ATT&CK tags)
    lines.append(f"OR (rule.threat.technique.id:{tid} OR threat.technique.id:{tid})")
    # Executable hints
    if exes:
        exe_list = " OR ".join(exes)
        lines.append(f"OR (event.category:process AND process.name:({exe_list}))")
    # Port hints
    if ports:
        port_list = " OR ".join(ports)
        lines.append(f"OR (event.category:network AND destination.port:({port_list}))")
    return "\n".join(lines)


def build_sysmon_xml(tech: dict, ds_info: dict) -> str:
    tid = tech["id"]
    name = tech["name"]
    tactic = tech.get("primary_tactic", "")
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))
    ports = extract_ports(tech.get("description", "") + " " + tech.get("detection", ""))

    sysmon_evt = ds_info.get("sysmon_evt") or "ProcessCreate"

    # Build event-specific rule
    if sysmon_evt == "ProcessCreate":
        if exes:
            image_cond = ";".join(f"\\{e}" for e in exes)
            inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Image condition="end with any">{image_cond}</Image>
      </Rule>"""
        else:
            inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Image condition="end with any">\\powershell.exe;\\cmd.exe;\\wscript.exe;\\cscript.exe;\\mshta.exe;\\regsvr32.exe;\\rundll32.exe</Image>
      </Rule>"""
        block = f"    <ProcessCreate onmatch=\"include\">\n{inner}\n    </ProcessCreate>"

    elif sysmon_evt == "ProcessAccess":
        inner = f"""      <Rule groupRelation="and" name="{name} - {tid}" technique="{tid}">
        <TargetImage condition="is">C:\\Windows\\System32\\lsass.exe</TargetImage>
        <GrantedAccess condition="is any">0x1010;0x1038;0x1418;0x1F1FFF;0x143A</GrantedAccess>
      </Rule>"""
        block = f"    <ProcessAccess onmatch=\"include\">\n{inner}\n    </ProcessAccess>"

    elif sysmon_evt == "NetworkConnect":
        if ports:
            port_list = ";".join(ports)
            inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <DestinationPort condition="is any">{port_list}</DestinationPort>
      </Rule>"""
        else:
            inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Initiated condition="is">true</Initiated>
      </Rule>"""
        block = f"    <NetworkConnect onmatch=\"include\">\n{inner}\n    </NetworkConnect>"

    elif sysmon_evt in ("FileCreate", "FileDelete"):
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <TargetFilename condition="contains any">.exe;.dll;.ps1;.vbs;.js;.bat;.cmd;.hta</TargetFilename>
      </Rule>"""
        block = f"    <{sysmon_evt} onmatch=\"include\">\n{inner}\n    </{sysmon_evt}>"

    elif sysmon_evt == "RegistryEvent":
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <TargetObject condition="contains any">\\Run;\\RunOnce;\\Services\\;\\Startup;\\CurrentVersion\\Image File Execution Options;\\Lsa\\Security Packages</TargetObject>
      </Rule>"""
        block = f"    <RegistryEvent onmatch=\"include\">\n{inner}\n    </RegistryEvent>"

    elif sysmon_evt == "DriverLoad":
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Signed condition="is">false</Signed>
      </Rule>"""
        block = f"    <DriverLoad onmatch=\"include\">\n{inner}\n    </DriverLoad>"

    elif sysmon_evt == "ImageLoad":
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Signed condition="is">false</Signed>
      </Rule>"""
        block = f"    <ImageLoad onmatch=\"include\">\n{inner}\n    </ImageLoad>"

    elif sysmon_evt == "WmiEvent":
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Name condition="contains">*</Name>
      </Rule>"""
        block = (
            f"    <WmiEventFilter onmatch=\"include\">\n{inner}\n    </WmiEventFilter>\n"
            f"    <WmiEventConsumer onmatch=\"include\">\n{inner}\n    </WmiEventConsumer>"
        )

    elif sysmon_evt == "PipeEvent":
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <PipeName condition="contains any">\\postex_;\\msagent_;\\mojo.;\\wkssvc;\\ntsvcs;\\lsadump</PipeName>
      </Rule>"""
        block = f"    <PipeEvent onmatch=\"include\">\n{inner}\n    </PipeEvent>"

    else:
        inner = f"""      <Rule groupRelation="or" name="{name} - {tid}" technique="{tid}">
        <Image condition="contains">*</Image>
      </Rule>"""
        block = f"    <ProcessCreate onmatch=\"include\">\n{inner}\n    </ProcessCreate>"

    return (
        f"<!-- Sysmon rule for {name} ({tid}) | Tactic: {tactic} -->\n"
        f"<Sysmon schemaversion=\"4.90\">\n"
        f"  <EventFiltering>\n"
        f"{block}\n"
        f"  </EventFiltering>\n"
        f"</Sysmon>"
    )


def build_osquery(tech: dict, ds_info: dict) -> str:
    tid = tech["id"]
    name = tech["name"]
    tbl = ds_info.get("osquery_tbl", "processes")
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))
    ports = extract_ports(tech.get("description", "") + " " + tech.get("detection", ""))

    if tbl == "processes":
        if exes:
            names_sql = ", ".join(f"'{e}'" for e in exes)
            return (
                f"-- OSQuery: {name} ({tid})\n"
                f"SELECT pid, name, path, cmdline, parent, start_time\n"
                f"FROM processes\n"
                f"WHERE name IN ({names_sql});\n\n"
                f"-- Correlate with open sockets if network-based\n"
                f"SELECT p.pid, p.name, s.remote_address, s.remote_port\n"
                f"FROM processes p JOIN process_open_sockets s ON p.pid = s.pid\n"
                f"WHERE p.name IN ({names_sql});"
            )
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT pid, name, path, cmdline, parent, start_time\n"
            f"FROM processes\n"
            f"WHERE cmdline LIKE '%-enc%'\n"
            f"   OR cmdline LIKE '%FromBase64String%'\n"
            f"   OR cmdline LIKE '%DownloadString%'\n"
            f"   OR cmdline LIKE '%Invoke-Expression%'\n"
            f"   OR name IN ('powershell.exe','cmd.exe','rundll32.exe','regsvr32.exe','mshta.exe','wmic.exe');"
        )

    elif tbl == "process_open_sockets":
        if ports:
            port_list = ", ".join(ports)
            return (
                f"-- OSQuery: {name} ({tid})\n"
                f"SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port, s.protocol\n"
                f"FROM processes p JOIN process_open_sockets s ON p.pid = s.pid\n"
                f"WHERE s.remote_port IN ({port_list});"
            )
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port\n"
            f"FROM processes p JOIN process_open_sockets s ON p.pid = s.pid\n"
            f"WHERE s.state = 'ESTABLISHED';"
        )

    elif tbl == "file":
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT filename, path, size, mtime, atime, ctime, type\n"
            f"FROM file\n"
            f"WHERE (\n"
            f"  path LIKE 'C:\\Users\\%\\AppData\\%'\n"
            f"  OR path LIKE 'C:\\Windows\\Temp\\%'\n"
            f"  OR path LIKE 'C:\\ProgramData\\%'\n"
            f") AND (\n"
            f"  filename LIKE '%.exe' OR filename LIKE '%.dll'\n"
            f"  OR filename LIKE '%.ps1' OR filename LIKE '%.vbs'\n"
            f");"
        )

    elif tbl == "registry":
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT key, path, name, data, mtime\n"
            f"FROM registry\n"
            f"WHERE key LIKE 'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run%'\n"
            f"   OR key LIKE 'HKEY_CURRENT_USER\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run%'\n"
            f"   OR key LIKE 'HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\%';"
        )

    elif tbl in ("services",):
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT name, display_name, status, path, pid, start_type\n"
            f"FROM services\n"
            f"WHERE start_type IN ('DEMAND_START','AUTO_START')\n"
            f"  AND path LIKE '%\\\\AppData\\\\%'\n"
            f"   OR path LIKE '%\\\\Temp\\\\%'\n"
            f"   OR path LIKE '%\\\\ProgramData\\\\%';"
        )

    elif tbl == "scheduled_tasks":
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT name, action, path, enabled, next_run_time\n"
            f"FROM scheduled_tasks\n"
            f"WHERE path LIKE '%AppData%' OR path LIKE '%Temp%' OR path LIKE '%ProgramData%';"
        )

    elif tbl == "logged_in_users":
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT liu.host, liu.time, liu.tty, liu.type, u.username\n"
            f"FROM logged_in_users liu\n"
            f"JOIN users u ON liu.uid = u.uid\n"
            f"WHERE liu.type != 'dead';"
        )

    elif tbl == "users":
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT username, description, directory, shell, uid, gid\n"
            f"FROM users\n"
            f"WHERE uid >= 1000 OR username NOT IN ('root','SYSTEM','daemon');"
        )

    else:
        return (
            f"-- OSQuery: {name} ({tid})\n"
            f"SELECT pid, name, path, cmdline, parent, start_time\n"
            f"FROM processes\n"
            f"WHERE name NOT IN ('svchost.exe','System','explorer.exe','RuntimeBroker.exe');"
        )


def build_velociraptor(tech: dict, ds_info: dict) -> str:
    tid = tech["id"]
    name = tech["name"]
    vql_src = ds_info.get("vql_source", "pslist()")
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))
    ports = extract_ports(tech.get("description", "") + " " + tech.get("detection", ""))

    if vql_src == "pslist()":
        if exes:
            exe_regex = "|".join(re.escape(e) for e in exes)
            return (
                f"-- Velociraptor VQL: {name} ({tid})\n"
                f"LET procs = SELECT Name, Exe, CommandLine, Pid, Ppid,\n"
                f"  authenticode(filename=Exe).Trusted AS Trusted\n"
                f"FROM pslist() WHERE Exe\n\n"
                f"SELECT Name, Exe, CommandLine, Pid, Ppid, Trusted\n"
                f"FROM procs\n"
                f"WHERE Exe =~ '(?i)({exe_regex})'\n"
                f"   OR NOT Trusted"
            )
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"LET procs = SELECT Name, Exe, CommandLine, Pid, Ppid,\n"
            f"  authenticode(filename=Exe).Trusted AS Trusted\n"
            f"FROM pslist() WHERE Exe\n\n"
            f"SELECT Name, Exe, CommandLine, Pid, Ppid, Trusted\n"
            f"FROM procs\n"
            f"WHERE NOT Trusted\n"
            f"   OR CommandLine =~ '(?i)(-enc|frombase64string|downloadstring|iex\\(|invoke-expression)'"
        )

    elif vql_src == "netstat()":
        if ports:
            port_list = ", ".join(ports)
            return (
                f"-- Velociraptor VQL: {name} ({tid})\n"
                f"SELECT Pid, Process, LocalAddress, LocalPort,\n"
                f"       RemoteAddress, RemotePort, Status\n"
                f"FROM netstat()\n"
                f"WHERE RemotePort IN ({port_list})"
            )
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT Pid, Process, LocalAddress, LocalPort,\n"
            f"       RemoteAddress, RemotePort, Status\n"
            f"FROM netstat()\n"
            f"WHERE Status = 'ESTABLISHED'\n"
            f"  AND RemoteAddress NOT IN ('127.0.0.1','::1')"
        )

    elif vql_src == "glob()":
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT FullPath, Mtime, Size, authenticode(filename=FullPath).Trusted AS Trusted\n"
            f"FROM glob(globs=['C:/Users/*/AppData/**/*.exe',\n"
            f"                 'C:/ProgramData/**/*.exe',\n"
            f"                 'C:/Windows/Temp/**/*.exe'])\n"
            f"WHERE Mtime > timestamp(epoch=now().Unix - 7*24*3600)"
        )

    elif vql_src in ("services()",):
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT Name, DisplayName, PathName, StartType, State\n"
            f"FROM services()\n"
            f"WHERE PathName =~ '(?i)(appdata|temp|programdata)'"
        )

    elif vql_src in ("ScheduledTasks()",):
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT Name, Command, Arguments, Enabled\n"
            f"FROM ScheduledTasks()\n"
            f"WHERE Command =~ '(?i)(powershell|cmd|wscript|cscript|mshta|rundll32)'"
        )

    elif vql_src == "users()":
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT Name, Uid, Gid, Homedir, Shell\n"
            f"FROM users()\n"
            f"WHERE Uid >= 1000"
        )

    elif vql_src == "modules()":
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT ModuleName, FileName,\n"
            f"  authenticode(filename=FileName).Trusted AS Trusted\n"
            f"FROM modules()\n"
            f"WHERE NOT Trusted"
        )

    else:
        return (
            f"-- Velociraptor VQL: {name} ({tid})\n"
            f"SELECT Name, Exe, CommandLine, Pid,\n"
            f"  authenticode(filename=Exe).Trusted AS Trusted\n"
            f"FROM pslist()\n"
            f"WHERE NOT Trusted"
        )


def build_elastic(tech: dict, ds_info: dict) -> str:
    tid = tech["id"]
    name = tech["name"]
    tactic = tech.get("primary_tactic", "")
    elastic_frag = ds_info.get("elastic", DS_FALLBACK["elastic"])
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))

    lines = [f"// Elastic KQL: {name} ({tid})"]
    lines.append(f"// MITRE ATT&CK: {tid} | Tactic: {tactic}")
    lines.append("")
    lines.append(elastic_frag)
    # Technique tag pivot
    lines.append(f'or (threat.technique.id: "{tid}")')
    if exes:
        exe_list = " or ".join(f'"{e}"' for e in exes)
        lines.append(f"or (process.name: ({exe_list}))")
    return "\n".join(lines)


def build_carbon_black(tech: dict, ds_info: dict) -> str:
    tid = tech["id"]
    name = tech["name"]
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))
    ports = extract_ports(tech.get("description", "") + " " + tech.get("detection", ""))

    parts = []
    if exes:
        exe_list = " OR ".join(f"process_name:{e}" for e in exes)
        parts.append(f"({exe_list})")
    if ports:
        port_list = " OR ".join(f"netconn_port:{p}" for p in ports)
        parts.append(f"({port_list})")
    if not parts:
        parts.append("process_name:(powershell.exe OR cmd.exe OR rundll32.exe OR regsvr32.exe OR mshta.exe OR wmic.exe)")

    return f"// Carbon Black: {name} ({tid})\n" + " AND ".join(parts)


def build_sigma_rule(tech: dict, ds_info: dict) -> str:
    """Generate a Sigma YAML detection rule for the technique."""
    tid = tech["id"]
    name = tech["name"]
    tactic = tech.get("primary_tactic", "unknown")
    domain = tech.get("domain", "enterprise")
    description_text = clean_text(tech.get("description", f"Detects {name}."))
    # Trim to 400 chars for Sigma description
    if len(description_text) > 400:
        description_text = description_text[:397] + "..."
    url = tech.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/")
    sig_id = str(uuid.uuid5(uuid.NAMESPACE_URL, url))
    today = date.today().isoformat()

    sysmon_evt = ds_info.get("sysmon_evt")
    exes = extract_exe_names(tech.get("description", "") + " " + tech.get("detection", ""))

    # Build logsource
    if sysmon_evt in ("ProcessCreate", "ProcessAccess", "DriverLoad", "ImageLoad", "PipeEvent"):
        logsource = "  category: process_creation\n  product: windows"
        if sysmon_evt == "ProcessAccess":
            logsource = "  category: process_access\n  product: windows"
        elif sysmon_evt == "DriverLoad":
            logsource = "  category: driver_loaded\n  product: windows"
        elif sysmon_evt == "ImageLoad":
            logsource = "  category: image_load\n  product: windows"
    elif sysmon_evt in ("NetworkConnect",):
        logsource = "  category: network_connection\n  product: windows"
    elif sysmon_evt in ("FileCreate", "FileDelete"):
        logsource = "  category: file_event\n  product: windows"
    elif sysmon_evt in ("RegistryEvent",):
        logsource = "  category: registry_event\n  product: windows"
    elif sysmon_evt == "WmiEvent":
        logsource = "  category: wmi_event\n  product: windows"
    elif "cloud" in domain.lower():
        logsource = "  category: cloud\n  product: aws"
    else:
        logsource = "  category: process_creation\n  product: windows"

    # Build detection block
    if exes and sysmon_evt in ("ProcessCreate", None):
        exe_yaml = "\n".join(f"      - '{e}'" for e in exes)
        detection_block = (
            f"  selection:\n"
            f"    Image|endswith:\n"
            f"{exe_yaml}\n"
            f"  condition: selection"
        )
    elif sysmon_evt == "ProcessAccess":
        detection_block = (
            "  selection:\n"
            "    TargetImage|endswith: '\\lsass.exe'\n"
            "    GrantedAccess|contains:\n"
            "      - '0x1010'\n"
            "      - '0x1038'\n"
            "      - '0x143A'\n"
            "      - '0x1418'\n"
            "  condition: selection"
        )
    elif sysmon_evt == "NetworkConnect":
        ports = extract_ports(tech.get("description", ""))
        if ports:
            port_yaml = "\n".join(f"      - {p}" for p in ports)
            detection_block = (
                "  selection:\n"
                "    DestinationPort:\n"
                f"{port_yaml}\n"
                "  condition: selection"
            )
        else:
            detection_block = (
                "  selection:\n"
                "    Initiated: 'true'\n"
                "  condition: selection"
            )
    elif sysmon_evt == "RegistryEvent":
        detection_block = (
            "  selection:\n"
            "    TargetObject|contains:\n"
            "      - '\\Run'\n"
            "      - '\\RunOnce'\n"
            "      - '\\Services\\'\n"
            "  condition: selection"
        )
    else:
        detection_block = (
            "  selection:\n"
            "    EventID: 1\n"
            "  condition: selection"
        )

    tid_lower = tid.lower().replace(".", "_")
    return (
        f"title: {name} Detection\n"
        f"id: {sig_id}\n"
        f"description: |\n"
        f"    {description_text}\n"
        f"status: experimental\n"
        f"references:\n"
        f"    - {url}\n"
        f"    - https://github.com/SigmaHQ/sigma\n"
        f"author: Generated from MITRE ATT&CK STIX data\n"
        f"date: {today}\n"
        f"modified: {today}\n"
        f"tags:\n"
        f"    - attack.{tactic}\n"
        f"    - attack.{tid_lower}\n"
        f"logsource:\n"
        f"{logsource}\n"
        f"detection:\n"
        f"{detection_block}\n"
        f"falsepositives:\n"
        f"    - Legitimate administrative activity\n"
        f"    - Security tooling\n"
        f"    - Software installation\n"
        f"level: medium"
    )


# ── Playbook Builder ─────────────────────────────────────────────────────────

def build_technique_playbook(tech: dict, num: int) -> dict:
    tid = tech["id"]
    name = tech["name"]
    domain = tech.get("domain", "enterprise")
    domain_label = {"enterprise": "Enterprise ATT&CK", "mobile": "Mobile ATT&CK", "ics": "ICS ATT&CK"}.get(domain, domain.title())
    description = clean_text(tech.get("description", ""))
    detection_guidance = clean_text(tech.get("detection", ""))
    primary_tactic = tech.get("primary_tactic", "")
    tactic_label = tech.get("tactic_label", primary_tactic.replace("-", " ").title())
    tactic_id = tech.get("tactic_id", "")
    all_tactics = tech.get("all_tactics", [primary_tactic])
    mitre_url = tech.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/")
    platforms = tech.get("platforms", [])
    data_sources = tech.get("data_sources", [])
    sev = TACTIC_SEVERITY.get(primary_tactic, "medium")
    is_subtechnique = "." in tid
    parent_id = tid.split(".")[0] if is_subtechnique else None

    # Choose DS info for query generation
    ds_info = _get_ds_info(data_sources)

    # Build scenario text
    scenario_parts = []
    if description:
        scenario_parts.append(description)
    if is_subtechnique and parent_id:
        scenario_parts.append(
            f"This is a sub-technique of [{parent_id}](https://attack.mitre.org/techniques/{parent_id}/)."
        )
    scenario_parts.append(
        f"Source: [{mitre_url}]({mitre_url})"
    )
    scenario = " ".join(scenario_parts)

    # Step 1: Technique profile
    tactic_list = ", ".join(t.replace("-", " ").title() for t in all_tactics)
    platform_list = ", ".join(platforms) if platforms else "Windows, Linux, macOS"
    ds_list = ", ".join(data_sources[:6]) if data_sources else "Process, Network, File"

    step1_detail = (
        f"MITRE ATT&CK ID: {tid}. Tactic(s): {tactic_list}. "
        f"Domain: {domain_label}. Platforms: {platform_list}. "
        f"Data sources: {ds_list}. "
        f"Reference: {mitre_url}"
    )
    if detection_guidance:
        step1_detail += f"\n\nMITRE Detection Guidance: {detection_guidance[:600]}"

    step1_queries = {
        "security_onion": (
            f"# Security Onion KQL – Profile {tid} in your environment\n"
            f"# Find any alert/rule that references this technique\n"
            f"(rule.threat.technique.id:{tid} OR threat.technique.id:{tid})\n"
            f"OR (rule.description:*{tid}* OR message:*{tid}*)"
        ),
        "sigma": (
            f"# Sigma: Search for existing rules tagged with {tid}\n"
            f"# Run: grep -r 'attack.{tid.lower().replace('.','_')}' sigma-rules/\n"
            f"# Or use: sigma search {tid}"
        ),
        "osquery": (
            f"-- OSQuery: Inventory for {tid} scope\n"
            f"SELECT pid, name, path, cmdline, parent, start_time\n"
            f"FROM processes\n"
            f"WHERE start_time > (strftime('%s','now') - 86400);"
        ),
        "velociraptor": (
            f"-- Velociraptor VQL: Recent process inventory for {tid}\n"
            f"SELECT Name, Exe, CommandLine, Pid,\n"
            f"  authenticode(filename=Exe).Trusted AS Trusted\n"
            f"FROM pslist()\n"
            f"WHERE CreateTime > timestamp(epoch=now().Unix - 86400)"
        ),
        "elastic": (
            f"// Elastic KQL: Find alerts for {tid}\n"
            f'threat.technique.id: "{tid}"\n'
            f'or rule.threat.technique.id: "{tid}"'
        ),
        "carbon_black": (
            f"// Carbon Black: Find events for {tid}\n"
            f"threat_id:{tid}"
        ),
    }

    # Step 2: Endpoint detection
    step2_queries = {
        "security_onion": build_security_onion_query(tech, ds_info),
        "sysmon": build_sysmon_xml(tech, ds_info),
        "osquery": build_osquery(tech, ds_info),
        "velociraptor": build_velociraptor(tech, ds_info),
        "elastic": build_elastic(tech, ds_info),
        "carbon_black": build_carbon_black(tech, ds_info),
        "sigma": build_sigma_rule(tech, ds_info),
    }

    # Step 3: Network / log telemetry
    ports = extract_ports(tech.get("description", "") + " " + tech.get("detection", ""))
    port_so = f" OR (event.dataset:zeek.conn AND destination.port:({' OR '.join(ports)}))" if ports else ""
    port_elastic = f" or destination.port: ({', '.join(ports)})" if ports else ""

    step3_queries = {
        "security_onion": (
            f"# Security Onion: Network/log telemetry for {tid}\n"
            f"(event.dataset:zeek.conn OR event.dataset:zeek.dns OR event.dataset:zeek.http OR event.dataset:suricata.eve)"
            f"{port_so}"
        ),
        "sysmon": step2_queries["sysmon"],  # Sysmon covers both endpoint and network
        "osquery": (
            f"-- OSQuery: Network connections for {tid}\n"
            f"SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port\n"
            f"FROM processes p JOIN process_open_sockets s ON p.pid = s.pid\n"
            f"WHERE s.state = 'ESTABLISHED';"
        ),
        "velociraptor": (
            f"-- Velociraptor VQL: Active network connections for {tid}\n"
            f"SELECT Pid, Process, LocalAddress, LocalPort,\n"
            f"       RemoteAddress, RemotePort, Status\n"
            f"FROM netstat()\n"
            f"WHERE Status = 'ESTABLISHED'\n"
            f"  AND RemoteAddress NOT IN ('127.0.0.1', '::1')"
        ),
        "elastic": (
            f"// Elastic: Network telemetry for {tid}\n"
            f'event.category: "network"\n'
            f'or event.dataset: "zeek.conn"\n'
            f"{port_elastic}"
        ),
        "carbon_black": (
            f"// Carbon Black: Network for {tid}\n"
            + (f"netconn_port:({' OR '.join(ports)})" if ports else "netconn_count:[1 TO *] AND NOT process_name:(chrome.exe OR msedge.exe OR firefox.exe)")
        ),
        "sigma": build_sigma_rule(tech, ds_info),
    }

    # Step 4: Investigate and correlate
    step4_queries = {
        "security_onion": (
            f"# Security Onion: Investigate {tid} - correlate endpoint + network\n"
            f"# Timeline pivot: use @timestamp range ±30 min around alert\n"
            f"(rule.threat.technique.id:{tid} OR threat.technique.id:{tid})\n"
            f"AND event.category:(process OR network OR file)"
        ),
        "sysmon": step2_queries["sysmon"],
        "osquery": (
            f"-- OSQuery: Pivot from PID to investigate {tid}\n"
            f"-- Replace :pid with the suspicious process ID\n"
            f"SELECT p.pid, p.name, p.path, p.cmdline, p.parent,\n"
            f"       f.filename, f.path AS file_path\n"
            f"FROM processes p\n"
            f"LEFT JOIN process_open_files f ON p.pid = f.pid\n"
            f"WHERE p.pid = :pid;"
        ),
        "velociraptor": (
            f"-- Velociraptor VQL: Full forensic triage for {tid}\n"
            f"LET proc = SELECT Name, Exe, CommandLine, Pid, Ppid,\n"
            f"  authenticode(filename=Exe).Trusted AS Trusted\n"
            f"FROM pslist()\n\n"
            f"SELECT * FROM proc WHERE NOT Trusted"
        ),
        "elastic": (
            f"// Elastic: Correlate {tid} events with user/host\n"
            f'threat.technique.id: "{tid}"\n'
            f'| stats count by host.name, user.name, process.name'
        ),
        "carbon_black": (
            f"// Carbon Black: Investigate {tid} by process tree\n"
            f"threat_id:{tid} AND childproc_count:[1 TO *]"
        ),
        "sigma": build_sigma_rule(tech, ds_info),
    }

    return {
        "id": f"tech-{tid.lower().replace('.', '-')}",
        "num": num,
        "name": f"{tid} – {name}",
        "fullName": f"{name} ({tid}) Detection Playbook",
        "type": f"{domain_label} Technique",
        "severity": sev.capitalize(),
        "priority": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(sev, "Medium"),
        "detection": "Security Onion, Sysmon, OSQuery, Velociraptor, Elastic, Carbon Black, Sigma",
        "scenario": scenario,
        "mitre": tid,
        "mitreUrl": mitre_url,
        "cat": "Techniques",
        "tactic": primary_tactic,
        "tacticId": tactic_id,
        "tacticLabel": tactic_label,
        "tacticOrder": ENTERPRISE_TACTIC_ORDER.index(primary_tactic) if primary_tactic in ENTERPRISE_TACTIC_ORDER else 99,
        "allTactics": all_tactics,
        "domain": domain,
        "domainLabel": domain_label,
        "platforms": platforms,
        "dataSources": data_sources,
        "isSubtechnique": is_subtechnique,
        "parentId": parent_id,
        "source": "library",
        "updated": date.today().isoformat(),
        "detSteps": [
            {
                "n": 1,
                "title": f"Profile {tid} – {name}",
                "detail": step1_detail,
                "queries": step1_queries,
            },
            {
                "n": 2,
                "title": "Detect with endpoint telemetry",
                "detail": (
                    f"Hunt for {name} using process, file, and registry telemetry. "
                    f"Primary data sources: {ds_list}. "
                    "Tune inclusions to your environment — suppress known-good software, patch management agents, and monitoring tools before alerting."
                ),
                "queries": step2_queries,
            },
            {
                "n": 3,
                "title": "Detect with network and log telemetry",
                "detail": (
                    "Correlate endpoint findings with network telemetry from Zeek, Suricata, and SIEM log sources. "
                    "Look for unusual outbound connections, DNS queries, and authentication events that align with the timeline of endpoint activity."
                ),
                "queries": step3_queries,
            },
            {
                "n": 4,
                "title": "Investigate and correlate",
                "detail": (
                    "Pivot from the initial finding to identify the full scope: parent processes, child processes, "
                    "lateral movement, credential access, and persistence mechanisms. Document your findings and preserve evidence."
                ),
                "queries": step4_queries,
            },
        ],
        "contSteps": [
            {
                "title": "Contain affected hosts and accounts",
                "detail": (
                    f"If {name} ({tid}) is confirmed: isolate affected endpoints, disable compromised accounts, "
                    "revoke active sessions, and block observed C2/exfiltration destinations. Preserve volatile memory and logs before isolation."
                ),
                "queries": {},
            },
        ],
        "eradSteps": [
            {
                "title": f"Remove {tid} artefacts and tooling",
                "detail": (
                    "Remove identified malicious files, scheduled tasks, services, registry keys, and unauthorized accounts. "
                    "Validate removal with Sysmon, OSQuery, or Velociraptor before reconnecting hosts."
                ),
                "queries": {},
            },
        ],
        "recSteps": [
            {
                "title": "Restore and harden",
                "detail": (
                    "Restore affected systems from trusted backups where required. Apply patches or configuration hardening "
                    f"that addresses the {name} vector. Tune detection queries with environment-specific exclusions and add coverage gaps to the detection backlog."
                ),
                "queries": {},
            },
        ],
    }


# ── Bundle Processing ─────────────────────────────────────────────────────────

def process_bundle(bundle: dict, domain: str) -> list[dict]:
    """Extract techniques and tactic metadata from a STIX bundle."""

    # First pass: build tactic map (x-mitre-tactic objects)
    tactic_by_slug: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue
        ref = None
        for r in obj.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                ref = r
                break
        if not ref:
            continue
        slug = obj.get("x_mitre_shortname", "")
        if slug:
            tactic_by_slug[slug] = {
                "id": ref.get("external_id", ""),
                "label": obj.get("name", slug.replace("-", " ").title()),
                "slug": slug,
            }

    # Build tactic order list for this domain
    if domain == "enterprise":
        tactic_order = ENTERPRISE_TACTIC_ORDER
    else:
        # Order by TA ID numeric value
        sorted_tactics = sorted(tactic_by_slug.values(), key=lambda t: t["id"])
        tactic_order = [t["slug"] for t in sorted_tactics]

    # Determine valid kill_chain_name values for this domain
    # Enterprise uses "mitre-attack"; Mobile uses "mitre-mobile-attack"; ICS uses "mitre-ics-attack"
    domain_chain_names = {
        "enterprise": {"mitre-attack"},
        "mobile": {"mitre-mobile-attack", "mitre-attack"},
        "ics": {"mitre-ics-attack", "mitre-attack"},
    }
    valid_chain_names = domain_chain_names.get(domain, {"mitre-attack"})

    # Second pass: build data-component, analytic, and detection-strategy maps
    strat_by_id: dict[str, dict] = {}
    analytic_by_id: dict[str, dict] = {}
    dc_by_id: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        t = obj.get("type")
        if t == "x-mitre-detection-strategy":
            strat_by_id[obj["id"]] = obj
        elif t == "x-mitre-analytic":
            analytic_by_id[obj["id"]] = obj
        elif t == "x-mitre-data-component":
            dc_by_id[obj["id"]] = obj

    # Technique STIX ID → list of data component names
    # Chain: technique ← detects rel ← strategy → analytic_refs → analytics → log_source_refs → dc_name
    technique_ds: dict[str, list[str]] = defaultdict(list)
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "detects":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tech_stix_id = obj.get("target_ref", "")
        strat = strat_by_id.get(obj.get("source_ref", ""), {})
        for analytic_ref in strat.get("x_mitre_analytic_refs", []):
            analytic = analytic_by_id.get(analytic_ref, {})
            for log_src in analytic.get("x_mitre_log_source_references", []):
                dc_name = dc_by_id.get(log_src.get("x_mitre_data_component_ref", ""), {}).get("name", "")
                if dc_name and dc_name not in technique_ds[tech_stix_id]:
                    technique_ds[tech_stix_id].append(dc_name)

    # Second pass: collect techniques
    techniques: list[dict] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = None
        for r in obj.get("external_references", []):
            if r.get("source_name") == "mitre-attack" and r.get("external_id", "").startswith("T"):
                ref = r
                break
        if not ref:
            continue

        tid = ref["external_id"]
        tactics_slugs = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") in valid_chain_names
        ]
        if not tactics_slugs:
            continue

        # Sort tactics by kill-chain order
        tactics_slugs = sorted(set(tactics_slugs), key=lambda s: tactic_sort_key(s, tactic_order))
        primary_tactic = tactics_slugs[0]
        tactic_info = tactic_by_slug.get(primary_tactic, {})

        techniques.append({
            "id": tid,
            "name": obj.get("name", tid),
            "description": clean_text(obj.get("description", "")),
            "detection": clean_text(obj.get("x_mitre_detection", "")),
            # Prefer v10+ relationship-based data sources; fall back to legacy string field
            "data_sources": (
                sorted(set(technique_ds.get(obj["id"], [])))
                or [str(ds) for ds in obj.get("x_mitre_data_sources", []) if isinstance(ds, str)]
            ),
            "platforms": obj.get("x_mitre_platforms", []),
            "url": ref.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
            "domain": domain,
            "primary_tactic": primary_tactic,
            "tactic_id": tactic_info.get("id", ""),
            "tactic_label": tactic_info.get("label", primary_tactic.replace("-", " ").title()),
            "all_tactics": tactics_slugs,
        })

    techniques.sort(key=lambda t: t["id"])
    return techniques


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    force = "--force" in sys.argv

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    existing_ids: set[str] = {item["id"] for item in manifest.get("playbooks", [])}
    max_num = max(
        (int(item.get("num", 0)) for item in manifest.get("playbooks", [])),
        default=0,
    )
    # Technique playbooks use a reserved block starting at TECH_NUM_BASE
    tech_counter = max(max_num, TECH_NUM_BASE - 1)

    TECH_DIR.mkdir(parents=True, exist_ok=True)

    total_added = 0
    total_updated = 0

    for domain_key, domain_cfg in DOMAINS.items():
        print(f"\n[{domain_key.upper()}] Fetching STIX bundle …")
        try:
            bundle = fetch_bundle(domain_cfg["url"])
        except Exception as exc:  # noqa: BLE001
            print(f"  ERROR: {exc}")
            continue

        techniques = process_bundle(bundle, domain_key)
        print(f"  Techniques extracted: {len(techniques)}")

        for tech in techniques:
            tid = tech["id"]
            playbook_id = f"tech-{tid.lower().replace('.', '-')}"
            primary_tactic = tech.get("primary_tactic", "unknown")
            tactic_slug = slugify(primary_tactic)
            tactic_dir = TECH_DIR / f"{tactic_slug}"
            tactic_dir.mkdir(parents=True, exist_ok=True)
            rel_file = f"techniques/{tactic_slug}/{playbook_id}-{slugify(tech['name'])}.json"

            already_in_manifest = playbook_id in existing_ids
            file_path = PLAYBOOK_ROOT / rel_file

            # Only write file if new or force-update requested
            if not file_path.exists() or force:
                tech_counter += 1
                playbook = build_technique_playbook(tech, tech_counter)
                file_path.write_text(
                    json.dumps(playbook, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                if not already_in_manifest:
                    total_added += 1
                else:
                    total_updated += 1

            if not already_in_manifest:
                # Add manifest entry (without incrementing counter again if file existed)
                if file_path.exists() and tech_counter == max(max_num, TECH_NUM_BASE - 1):
                    tech_counter += 1
                manifest["playbooks"].append(
                    {
                        "id": playbook_id,
                        "num": tech_counter,
                        "name": f"{tid} – {tech['name']}",
                        "cat": "Techniques",
                        "tactic": primary_tactic,
                        "tacticId": tech.get("tactic_id", ""),
                        "tacticLabel": tech.get("tactic_label", ""),
                        "domain": domain_key,
                        "sev": TACTIC_SEVERITY.get(primary_tactic, "medium"),
                        "type": f"{domain_cfg['label']} Technique",
                        "mitre": tid,
                        "isSubtechnique": "." in tid,
                        "source": "library",
                        "file": rel_file,
                    }
                )
                existing_ids.add(playbook_id)

    manifest["generated"] = date.today().isoformat()
    MANIFEST_PATH.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        "\n"
        + textwrap.dedent(
            f"""\
            ─────────────────────────────────────────
            Technique playbooks added:   {total_added}
            Technique playbooks updated: {total_updated}
            Manifest total entries:      {len(manifest['playbooks'])}
            Output directory:            {TECH_DIR}
            ─────────────────────────────────────────
            """
        ).strip()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
