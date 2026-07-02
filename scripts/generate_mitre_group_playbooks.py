#!/usr/bin/env python3
"""Generate default playbooks for MITRE ATT&CK Enterprise groups.

The generator is intentionally deterministic: it fetches the public MITRE
Enterprise ATT&CK STIX bundle, creates one default library playbook per
intrusion-set/group (Gxxxx), and appends only missing entries to the manifest.
"""

from __future__ import annotations

import json
import re
import textwrap
import urllib.request
from collections import defaultdict
from datetime import date
from pathlib import Path


ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROOT = ROOT / "app" / "playbooks"
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
    with urllib.request.urlopen(ATTACK_URL, timeout=120) as response:
        return json.load(response)


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


def technique_ids_for_query(techniques: list[dict], limit: int = 20) -> str:
    ids = [tech["id"] for tech in techniques[:limit]]
    return " OR ".join(ids) if ids else "Gxxxx"


def common_sysmon_xml(group_name: str, techniques: list[dict]) -> str:
    tech_ids = ",".join(tech["id"] for tech in techniques[:8]) or "Gxxxx"
    return f"""<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Rule groupRelation="or" name="{group_name} - ATT&CK process behavior" technique="{tech_ids}">
        <CommandLine condition="contains any">-enc;-encodedcommand;IEX;FromBase64String;DownloadString;regsvr32;mshta;wmic;winrs;rundll32</CommandLine>
        <Image condition="end with any">\\powershell.exe;\\cmd.exe;\\wscript.exe;\\cscript.exe;\\mshta.exe;\\regsvr32.exe;\\rundll32.exe;\\wmic.exe;\\winrs.exe</Image>
      </Rule>
    </ProcessCreate>
    <ProcessAccess onmatch="include">
      <Rule groupRelation="and" name="{group_name} - Credential access candidate" technique="T1003">
        <TargetImage condition="is">C:\\Windows\\System32\\lsass.exe</TargetImage>
        <SourceImage condition="end with any">\\procdump.exe;\\rundll32.exe;\\powershell.exe;\\mimikatz.exe</SourceImage>
      </Rule>
    </ProcessAccess>
    <NetworkConnect onmatch="include">
      <Rule groupRelation="or" name="{group_name} - C2 and lateral movement ports" technique="T1071,T1021">
        <DestinationPort condition="is any">53;80;443;445;3389;5985;5986;8080;8443</DestinationPort>
      </Rule>
    </NetworkConnect>
    <RegistryEvent onmatch="include">
      <Rule groupRelation="or" name="{group_name} - Persistence and defense evasion registry changes" technique="T1547,T1562">
        <TargetObject condition="contains any">\\Run;\\RunOnce;\\Services\\;\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication;\\Lsa\\Security Packages</TargetObject>
      </Rule>
    </RegistryEvent>
    <DnsQuery onmatch="include">
      <QueryName condition="contains any">.top;.xyz;.club;.online;.site;.cc</QueryName>
    </DnsQuery>
  </EventFiltering>
</Sysmon>"""


def build_detection_steps(group: dict, techniques: list[dict]) -> list[dict]:
    group_name = group["name"]
    group_id = group["mitre_id"]
    top_techniques = technique_summary(techniques)
    query_ids = technique_ids_for_query(techniques)
    aliases = ", ".join(group.get("aliases", [])[:12]) or "No public aliases listed"
    tactics = tactic_summary(techniques)
    mitre_url = group.get("url") or f"https://attack.mitre.org/groups/{group_id}/"

    security_onion_base = (
        f"# Security Onion KQL - {group_name} ({group_id}) ATT&CK technique pivots\n"
        f"(rule.threat.technique.id:({query_ids}) OR threat.technique.id:({query_ids}) "
        f"OR event.module:sysmon OR event.dataset:suricata.eve OR event.dataset:zeek.*)"
    )
    osquery_process = """SELECT pid, name, path, cmdline, parent, start_time
FROM processes
WHERE cmdline LIKE '%-enc%'
   OR cmdline LIKE '%FromBase64String%'
   OR cmdline LIKE '%DownloadString%'
   OR name IN ('powershell.exe','cmd.exe','rundll32.exe','regsvr32.exe','mshta.exe','wmic.exe','winrs.exe');"""
    velociraptor_process = """LET procs = SELECT Name, Exe, CommandLine, Pid,
  authenticode(filename=Exe).Trusted AS Trusted
FROM pslist() WHERE Exe
SELECT Name, Exe, CommandLine, Pid, Trusted
FROM procs
WHERE NOT Trusted OR CommandLine =~ '(?i)(-enc|frombase64string|downloadstring|regsvr32|mshta|wmic|winrs)'"""

    return [
        {
            "n": 1,
            "title": f"Profile {group_name} with MITRE ATT&CK context",
            "detail": (
                f"MITRE Group ID: {group_id}. Aliases: {aliases}. Primary mapped tactics: {tactics}. "
                f"Mapped techniques: {top_techniques}. Source: {mitre_url}. Use this step to scope the hunt, "
                "select relevant telemetry, and prioritize techniques that overlap the current alert or campaign."
            ),
            "queries": {
                "security_onion": security_onion_base,
                "sysmon": common_sysmon_xml(group_name, techniques),
                "osquery": osquery_process,
                "velociraptor": velociraptor_process,
                "elastic": security_onion_base.replace("Security Onion KQL", "Elastic KQL"),
                "carbon_black": "process_name:(powershell.exe OR cmd.exe OR rundll32.exe OR regsvr32.exe OR mshta.exe OR wmic.exe OR winrs.exe) OR netconn_count:[1 TO *]",
            },
        },
        {
            "n": 2,
            "title": "Hunt initial access, execution, and persistence behaviors",
            "detail": (
                "Search for public-facing exploitation, suspicious script execution, LOLBins, web shells, scheduled tasks, "
                "service creation, and autorun registry changes. Tune by asset role: web servers, domain controllers, and "
                "admin jump boxes should have separate baselines."
            ),
            "queries": {
                "security_onion": """# Initial access/execution/persistence hunt
(event.category:process AND process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe OR regsvr32.exe OR rundll32.exe))
OR (event.category:file AND file.extension:(aspx OR jsp OR php OR ps1 OR vbs OR js))
OR (event.code:(4698 OR 4702 OR 7045))
OR (registry.path:*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run* OR registry.path:*\\SYSTEM\\CurrentControlSet\\Services\\*)""",
                "sysmon": common_sysmon_xml(group_name, techniques),
                "osquery": """SELECT name, action, path FROM scheduled_tasks
UNION
SELECT name, path, status FROM services
WHERE path LIKE '%AppData%' OR path LIKE '%Temp%' OR path LIKE '%ProgramData%';""",
                "velociraptor": """SELECT FullPath, Mtime, Size
FROM glob(globs=['C:/inetpub/wwwroot/**/*.aspx','C:/ProgramData/**/*.ps1','C:/Users/*/AppData/**/*.exe'])
WHERE Mtime > timestamp(epoch=now().Unix - 7*24*60*60)""",
                "elastic": """event.category:"process" and process.name:("powershell.exe" or "cmd.exe" or "mshta.exe" or "regsvr32.exe" or "rundll32.exe")""",
                "carbon_black": "(process_name:powershell.exe OR process_name:cmd.exe OR process_name:mshta.exe OR process_name:regsvr32.exe OR process_name:rundll32.exe) AND (cmdline:-enc OR cmdline:DownloadString OR cmdline:FromBase64String OR cmdline:http)",
            },
        },
        {
            "n": 3,
            "title": "Hunt credential access, discovery, and lateral movement",
            "detail": (
                "Prioritize LSASS access, SAM/SECURITY hive reads, domain and network discovery, RDP/SMB/WinRM movement, "
                "and authentication anomalies. Correlate endpoint process telemetry with Zeek conn/smb/kerberos logs."
            ),
            "queries": {
                "security_onion": """# Credential access + discovery + lateral movement
(event.module:sysmon AND event.code:10 AND process.Ext.api.target_process.executable:*\\lsass.exe)
OR (event.category:process AND process.command_line:(*nltest* OR *net group* OR *net view* OR *whoami /all* OR *ipconfig /all*))
OR (event.category:network AND destination.port:(88 OR 135 OR 139 OR 389 OR 445 OR 3389 OR 5985 OR 5986))""",
                "sysmon": common_sysmon_xml(group_name, techniques),
                "osquery": """SELECT * FROM process_open_sockets
WHERE remote_port IN (88,135,139,389,445,3389,5985,5986);

SELECT pid, name, cmdline FROM processes
WHERE cmdline LIKE '%nltest%' OR cmdline LIKE '%net group%' OR cmdline LIKE '%whoami /all%' OR cmdline LIKE '%ipconfig /all%';""",
                "velociraptor": """SELECT Pid, Process, LocalAddress, LocalPort, RemoteAddress, RemotePort, Status
FROM netstat()
WHERE RemotePort IN (88,135,139,389,445,3389,5985,5986)""",
                "elastic": """event.category:"network" and destination.port:(88 or 135 or 139 or 389 or 445 or 3389 or 5985 or 5986)""",
                "carbon_black": "netconn_port:(88 OR 135 OR 139 OR 389 OR 445 OR 3389 OR 5985 OR 5986) OR cmdline:(nltest OR \"net group\" OR \"whoami /all\")",
            },
        },
        {
            "n": 4,
            "title": "Hunt command-and-control, ingress transfer, and exfiltration",
            "detail": (
                "Look for rare outbound destinations, DNS TXT/NULL or high-entropy queries, suspicious HTTP POST activity, "
                "proxy-like behavior, and large outbound transfers. Baseline by subnet and server role before suppressing."
            ),
            "queries": {
                "security_onion": """# C2 and exfiltration hunt
(event.category:network AND destination.port:(53 OR 80 OR 443 OR 8080 OR 8443 OR 1080 OR 8888))
OR (event.dataset:zeek.dns AND (dns.question.type:(TXT OR NULL) OR dns.question.name:*[A-Za-z0-9]{20,}*))
OR (event.dataset:zeek.http AND http.request.method:POST AND (network.bytes:>1000000 OR bytes:>1000000))
OR (event.dataset:suricata.eve AND event.kind:alert)""",
                "sysmon": common_sysmon_xml(group_name, techniques),
                "osquery": """SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port
FROM processes p
JOIN process_open_sockets s ON p.pid = s.pid
WHERE s.remote_port IN (53,80,443,8080,8443,1080,8888);""",
                "velociraptor": """SELECT Pid, Process, RemoteAddress, RemotePort, Status
FROM netstat()
WHERE RemotePort IN (53,80,443,8080,8443,1080,8888)""",
                "elastic": """event.category:"network" and destination.port:(53 or 80 or 443 or 8080 or 8443 or 1080 or 8888)""",
                "carbon_black": "netconn_port:(53 OR 80 OR 443 OR 8080 OR 8443 OR 1080 OR 8888) AND NOT process_name:(chrome.exe OR msedge.exe OR firefox.exe OR outlook.exe OR teams.exe)",
            },
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
        "name": f"Group — {group_name}",
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
        if playbook_id in existing_ids or rel_file in existing_files:
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
        manifest["playbooks"].append(
            {
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
            }
        )
        added += 1

    manifest["generated"] = date.today().isoformat()
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(
        textwrap.dedent(
            f"""\
            MITRE Enterprise groups processed: {len(groups)}
            New default group playbooks added: {added}
            Manifest total playbooks: {len(manifest['playbooks'])}
            """
        ).strip()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
