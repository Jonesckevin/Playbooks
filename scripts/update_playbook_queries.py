#!/usr/bin/env python3
"""Update non-technique library playbooks with Security Onion, osquery, Elastic, and Sigma queries.

Reads every playbook JSON in app/playbooks/ (excluding techniques/, threat-groups/,
manifest.json, mitre-techniques.json) and adds missing query platforms:
  - security_onion  (Kibana KQL with ECS/Zeek/Suricata fields)
  - osquery         (SQL against osquery tables)
  - elastic         (Elastic KQL)
  - sigma           (YAML detection rule)

Existing platform queries are preserved; only MISSING ones are added.
Writes back to the same file.

Usage:
    python scripts/update_playbook_queries.py [--force] [--file BASENAME]
"""
from __future__ import annotations

import json
import re
import sys
import uuid
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_DIR = ROOT / "app" / "playbooks"
SKIP_DIRS = {"techniques", "threat-groups"}
SKIP_FILES = {"manifest.json", "mitre-techniques.json"}

FORCE = "--force" in sys.argv
FILE_FILTER = None
for i, arg in enumerate(sys.argv[1:]):
    if arg == "--file" and i + 1 < len(sys.argv) - 1:
        FILE_FILTER = sys.argv[i + 2]

TODAY = date.today().isoformat()


# ── Helpers ────────────────────────────────────────────────────────────────────
def clean(text: str | None) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", str(text)).strip()


def has_query(v) -> bool:
    if not v:
        return False
    s = str(v).strip()
    return bool(s) and s.lower() not in ("none", "null", "{}", "[]")


def sigma_uid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"playbook-{name}"))


def keywords_in(texts: list[str], *kws) -> bool:
    combined = " ".join(texts).lower()
    return any(k in combined for k in kws)


# ── Category + step-aware query generators ─────────────────────────────────────

def generate_queries(pb: dict, step: dict, step_idx: int) -> dict[str, str]:
    """Return {platform: query} for the missing platforms in this step."""
    pb_name = clean(pb.get("name", ""))
    pb_cat = (pb.get("cat") or pb.get("type") or "").lower()
    pb_scenario = clean(pb.get("scenario", ""))[:300]
    step_title = clean(step.get("title", "")).lower()
    step_detail = clean(step.get("detail", ""))[:300]
    existing = step.get("queries", {}) or {}

    # Use existing Splunk query for context if available
    splunk_ctx = str(existing.get("splunk", "") or existing.get("kql", "") or "")[:200]

    # All texts for keyword detection
    ctx = [pb_name, pb_cat, pb_scenario, step_title, step_detail, splunk_ctx]

    # Determine detection type from keywords
    is_auth      = keywords_in(ctx, "auth", "login", "credential", "password", "brute", "mfa", "rdp", "logon", "kerberos", "oauth", "saml", "sso", "token", "session")
    is_cloud     = keywords_in(ctx, "cloud", "aws", "azure", "gcp", "s3", "blob", "cloudtrail", "iam", "saas", "o365", "google workspace", "office 365")
    is_ransomware= keywords_in(ctx, "ransom", "encrypt", "locked", "shadow", "vss", "bcdedit", "wbadmin")
    is_exfil     = keywords_in(ctx, "exfiltrat", "data transfer", "exfil", "dns tunnel", "large transfer", "bytes out")
    is_web       = keywords_in(ctx, "web", "http", "sql injection", "xss", "api", "application", "endpoint", "request", "sqli", "url", "path traversal")
    is_email     = keywords_in(ctx, "email", "phish", "bec", "mailbox", "inbox rule", "mail", "o365", "exchange", "forwarding")
    is_network   = keywords_in(ctx, "network", "lateral", "smb", "arp", "mitm", "dns attack", "lateral movement", "firewall", "traffic")
    is_supply    = keywords_in(ctx, "supply chain", "ci/cd", "pipeline", "package", "dependency", "build", "artifact", "npm", "pypi", "maven")
    is_container = keywords_in(ctx, "container", "docker", "kubernetes", "k8s", "pod", "namespace", "escape", "breakout")
    is_lolbin    = keywords_in(ctx, "lolbin", "living off the land", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "wmic", "msconfig")
    is_usb       = keywords_in(ctx, "usb", "removable", "media", "autorun")
    is_process   = keywords_in(ctx, "process", "execution", "command", "shell", "powershell", "script", "malware", "backdoor", "reverse shell")
    is_file      = keywords_in(ctx, "file", "artifact", "dropped", "payload", "implant")
    is_insider   = keywords_in(ctx, "insider", "employee", "privilege", "escalation", "staging", "sensitive data")
    is_discovery = keywords_in(ctx, "discovery", "reconnaissance", "enumeration", "inventory", "scan")
    is_impact    = keywords_in(ctx, "impact", "destroy", "disrupt", "ddos", "denial", "shutdown", "stop service")
    is_zero_day  = keywords_in(ctx, "zero-day", "zero day", "cve", "vulnerability", "exploit", "patch")
    is_shadow_it = keywords_in(ctx, "shadow it", "unauthorised saas", "unsanctioned", "unapproved tool")
    is_ai_tool   = keywords_in(ctx, "generative ai", "chatgpt", "copilot", "llm", "gpt", "ai tool")

    so = _build_so(ctx, pb_cat, step_title, step_idx,
                   is_auth, is_cloud, is_ransomware, is_exfil, is_web, is_email,
                   is_network, is_supply, is_container, is_lolbin, is_usb, is_process,
                   is_file, is_insider, is_discovery, is_impact, is_zero_day,
                   is_shadow_it, is_ai_tool, splunk_ctx, pb_name)
    osq = _build_osquery(ctx, step_title, step_idx,
                         is_auth, is_cloud, is_ransomware, is_exfil, is_web, is_email,
                         is_network, is_supply, is_container, is_lolbin, is_usb, is_process,
                         is_file, is_insider, is_shadow_it, is_ai_tool, pb_name)
    elastic = _build_elastic(so)  # Elastic KQL closely mirrors SO KQL
    sigma = _build_sigma(pb_name, step_title, is_auth, is_ransomware, is_lolbin,
                         is_process, is_exfil, is_network, is_email, is_web, is_cloud)

    result: dict[str, str] = {}
    if not has_query(existing.get("security_onion")) or FORCE:
        result["security_onion"] = so
    if not has_query(existing.get("osquery")) or FORCE:
        result["osquery"] = osq
    if not has_query(existing.get("elastic")) or FORCE:
        result["elastic"] = elastic
    if not has_query(existing.get("sigma")) or FORCE:
        result["sigma"] = sigma
    return result


def _build_so(ctx, pb_cat, step_title, step_idx,
              is_auth, is_cloud, is_ransomware, is_exfil, is_web, is_email,
              is_network, is_supply, is_container, is_lolbin, is_usb, is_process,
              is_file, is_insider, is_discovery, is_impact, is_zero_day,
              is_shadow_it, is_ai_tool, splunk_ctx, pb_name) -> str:

    lines = [f"# Security Onion KQL — {pb_name} (step {step_idx + 1})"]

    if is_ransomware:
        lines += [
            "# Ransomware precursors: VSS deletion, rapid file modification, ransom notes",
            "# Shadow copy deletion",
            "event.code:1 AND (process.name:vssadmin.exe AND process.command_line:*delete*)",
            "OR (process.name:bcdedit.exe AND process.command_line:*norecoveryenabled*)",
            "OR (process.name:wbadmin.exe AND process.command_line:*delete*)",
            "",
            "# Ransom note file creation",
            "event.module:sysmon AND event.code:11",
            "  AND (file.name:*README* OR file.name:*DECRYPT* OR file.name:*RECOVER*",
            "       OR file.name:*.locked OR file.name:*.encrypted OR file.name:*.crypt)",
            "",
            "# Lateral SMB propagation",
            "event.dataset:zeek.conn AND destination.port:445",
            "  AND NOT (source.ip:10.0.0.0/8 OR source.ip:172.16.0.0/12 OR source.ip:192.168.0.0/16)",
        ]

    elif is_email:
        lines += [
            "# BEC / phishing email indicators",
            "# Mailbox rule creation (forwarding — requires O365/EWS log ingest)",
            "event.action:(\"Add-MailboxPermission\" OR \"New-InboxRule\" OR \"Set-InboxRule\")",
            "  AND (winlog.event_data.Parameters:*ForwardTo* OR winlog.event_data.Parameters:*DeliverToMailbox*)",
            "",
            "# Office application spawning shell (phishing payload)",
            "event.code:1",
            "  AND process.parent.name:(winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe)",
            "  AND process.name:(powershell.exe OR cmd.exe OR wscript.exe OR mshta.exe)",
            "",
            "# Suricata phishing signature",
            "event.dataset:suricata.eve AND event.kind:alert",
            "  AND (suricata.alert.signature:*phish* OR suricata.alert.category:\"Attempted User Privilege Gain\")",
        ]

    elif is_auth:
        lines += [
            "# Authentication anomalies",
            "# Failed logins — brute force threshold",
            "event.code:4625 AND event.provider:Microsoft-Windows-Security-Auditing",
            "# Kibana Threshold Alert: count >= 10 per source IP in 60s → brute force",
            "",
            "# Successful login after failures (credential stuffing hit)",
            "event.code:4624 AND event.provider:Microsoft-Windows-Security-Auditing",
            "  AND winlog.event_data.LogonType:(3 OR 10)",
            "",
            "# Kerberos RC4 downgrade (Kerberoasting)",
            "event.code:4769 AND winlog.event_data.TicketEncryptionType:0x17",
            "  AND NOT winlog.event_data.ServiceName:*$",
            "",
            "# Zeek auth logs",
            "event.dataset:zeek.kerberos AND zeek.kerberos.success:false",
        ]

    elif is_cloud:
        lines += [
            "# Cloud platform activity anomalies",
            "# AWS CloudTrail: unusual API calls, impossible travel",
            "event.dataset:aws.cloudtrail AND event.outcome:failure",
            "",
            "# AWS console login from unexpected source",
            "event.dataset:aws.cloudtrail AND event.action:ConsoleLogin",
            "  AND NOT source.ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)",
            "",
            "# Azure activity log anomalies",
            "event.dataset:azure.activitylogs AND event.outcome:failure",
            "",
            "# GCP audit logs",
            "event.dataset:gcp.audit AND event.outcome:failure",
            "",
            "# Cloud CLI processes on endpoints",
            "event.code:1 AND process.name:(aws.exe OR gcloud.exe OR az.exe OR kubectl.exe)",
        ]

    elif is_exfil or ("dns" in " ".join(ctx).lower() and "tunnel" in " ".join(ctx).lower()):
        lines += [
            "# Data exfiltration indicators",
            "# Large outbound transfers (Zeek conn)",
            "event.dataset:zeek.conn AND network.bytes:>10000000",
            "  AND NOT (destination.ip:10.0.0.0/8 OR destination.ip:172.16.0.0/12 OR destination.ip:192.168.0.0/16)",
            "",
            "# DNS tunneling: high-entropy or long DNS queries",
            "event.dataset:zeek.dns AND dns.question.name.length:>50",
            "",
            "# DNS TXT record exfiltration",
            "event.dataset:zeek.dns AND dns.question.type:TXT",
            "",
            "# HTTP POST upload to external",
            "event.dataset:zeek.http AND http.request.method:POST AND network.bytes:>1000000",
        ]

    elif is_web:
        lines += [
            "# Web application attack detection",
            "# Suricata web attack signatures",
            "event.dataset:suricata.eve AND event.kind:alert",
            "  AND (suricata.alert.category:(\"Web Application Attack\" OR \"Attempted Information Leak\")",
            "       OR suricata.alert.signature:(*sqli* OR *xss* OR *path.traversal* OR *rce* OR *webshell*))",
            "",
            "# Zeek HTTP: suspicious patterns in URIs",
            "event.dataset:zeek.http",
            "  AND (url.path:*union+select* OR url.path:*<script* OR url.path:*../* OR url.path:*cmd=*)",
            "",
            "# Web server spawning shell (RCE / web shell execution)",
            "event.code:1",
            "  AND process.parent.name:(w3wp.exe OR httpd.exe OR nginx.exe OR php-fpm OR node)",
            "  AND process.name:(cmd.exe OR powershell.exe OR sh OR bash OR python.exe)",
        ]

    elif is_network:
        lines += [
            "# Network attack detection",
            "# Zeek conn: unusual traffic patterns",
            "event.dataset:zeek.conn AND network.bytes:>1000000",
            "  AND NOT (destination.ip:10.0.0.0/8 OR destination.ip:172.16.0.0/12)",
            "",
            "# ARP anomalies / MITM indicators",
            "event.dataset:zeek.arp",
            "",
            "# Suricata network attack signatures",
            "event.dataset:suricata.eve AND event.kind:alert",
            "  AND suricata.alert.category:(\"Attempted Administrator Privilege Gain\" OR \"Potential Corporate Privacy Violation\")",
            "",
            "# SMB lateral movement",
            "event.dataset:zeek.conn AND destination.port:445",
        ]

    elif is_container:
        lines += [
            "# Container breakout / privileged container",
            "# Container process spawning host processes",
            "event.code:1 AND process.name:(nsenter OR chroot OR unshare)",
            "",
            "# Kubernetes API anomalies",
            "event.dataset:(kubernetes.audit OR docker.*)",
            "  AND event.outcome:failure",
            "",
            "# Suricata container anomaly",
            "event.dataset:suricata.eve AND event.kind:alert",
            "  AND suricata.alert.signature:*container*",
        ]

    elif is_lolbin:
        lines += [
            "# LOLBin (Living-off-the-Land Binary) abuse",
            "event.code:1 AND (",
            "  (process.name:rundll32.exe AND process.command_line:(*.dll* AND (*http* OR *temp* OR *appdata*)))",
            "  OR (process.name:regsvr32.exe AND process.command_line:(*http* OR *scrobj*))",
            "  OR (process.name:mshta.exe AND process.command_line:(*http* OR *.hta*))",
            "  OR (process.name:certutil.exe AND process.command_line:(*decode* OR *urlcache* OR *http*))",
            "  OR (process.name:bitsadmin.exe AND process.command_line:*transfer*)",
            "  OR (process.name:wmic.exe AND process.command_line:*process*create*)",
            ")",
        ]

    elif is_usb:
        lines += [
            "# USB device / removable media attack",
            "# USB device insertion and autorun execution",
            "event.code:1 AND process.command_line:(autorun.inf OR *removable* OR *USB*)",
            "",
            "# File creation from removable media paths",
            "event.module:sysmon AND event.code:11",
            "  AND (file.path:*:\\* AND NOT file.path:(C:\\* OR D:\\*))",
            "",
            "# Sysmon Event 6 (DriverLoad) — USB driver",
            "event.module:sysmon AND event.code:6 AND winlog.event_data.Signed:false",
        ]

    elif is_supply:
        lines += [
            "# Supply chain / CI-CD attack",
            "# Suspicious build process activity",
            "event.code:1 AND (",
            "  process.parent.name:(jenkins.exe OR gitlab-runner.exe OR github-actions-runner.exe)",
            "  AND process.name:(powershell.exe OR cmd.exe OR bash OR curl.exe OR wget.exe)",
            ")",
            "",
            "# Package manager downloading unusual artifacts",
            "event.code:1 AND process.name:(npm.cmd OR pip.exe OR mvn.exe OR gradle) AND network.packets.orig:>1",
            "",
            "# Suricata: suspicious download patterns",
            "event.dataset:suricata.eve AND event.kind:alert AND suricata.alert.signature:*malware*",
        ]

    elif is_shadow_it or is_ai_tool:
        lines += [
            "# Shadow IT / Unauthorized SaaS / AI tool usage",
            "# Zeek HTTP: connections to shadow IT or AI services",
            "event.dataset:zeek.http AND (",
            "  destination.domain:(*.notion.so OR *.airtable.com OR *.trello.com OR *.monday.com)",
            "  OR destination.domain:(*.openai.com OR *.anthropic.com OR *.perplexity.ai OR *.chat.com)",
            "  OR destination.domain:(*.dropbox.com OR *.box.com OR *.wetransfer.com)",
            ")",
            "",
            "# Suricata policy violation",
            "event.dataset:suricata.eve AND event.kind:alert",
            "  AND suricata.alert.category:\"Potential Corporate Privacy Violation\"",
        ]

    elif is_discovery:
        lines += [
            "# Discovery and reconnaissance activity",
            "event.code:1 AND process.name:(net.exe OR net1.exe OR whoami.exe OR systeminfo.exe OR ipconfig.exe OR nltest.exe)",
            "",
            "# LDAP enumeration",
            "event.dataset:zeek.conn AND destination.port:389",
            "",
            "# Suricata recon signatures",
            "event.dataset:suricata.eve AND event.kind:alert AND suricata.alert.signature:*scan*",
        ]

    elif is_impact:
        lines += [
            "# Impact / DoS / service disruption",
            "# DDoS traffic spike",
            "event.dataset:zeek.conn AND destination.port:(80 OR 443) AND network.bytes:>100000",
            "",
            "# Service stop commands",
            "event.code:1 AND process.name:sc.exe AND process.command_line:*stop*",
            "",
            "# Suricata DoS signatures",
            "event.dataset:suricata.eve AND event.kind:alert",
            "  AND suricata.alert.category:(\"Denial of Service\" OR \"Web Application Attack\")",
        ]

    else:  # Generic process/file detection
        lines += [
            "# Process and file activity detection",
            "event.code:1 AND process.name:(powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe)",
            "  AND (process.parent.name:(winword.exe OR excel.exe OR outlook.exe OR explorer.exe)",
            "       OR process.command_line:(*-enc* OR *base64* OR *DownloadString* OR *IEX*))",
            "",
            "# Suricata alerts",
            "event.dataset:suricata.eve AND event.kind:alert",
            "",
            "# Network connections from suspicious processes",
            "event.module:sysmon AND event.code:3 AND process.name:(powershell.exe OR cmd.exe OR wscript.exe)",
        ]

    return "\n".join(lines)


def _build_osquery(ctx, step_title, step_idx,
                   is_auth, is_cloud, is_ransomware, is_exfil, is_web, is_email,
                   is_network, is_supply, is_container, is_lolbin, is_usb, is_process,
                   is_file, is_insider, is_shadow_it, is_ai_tool, pb_name) -> str:

    lines = [f"-- OSQuery: {pb_name} (step {step_idx + 1})"]

    if is_ransomware:
        lines += [
            "-- Check for high file-write processes (ransomware encryption activity)",
            "SELECT pid, name, path, cmdline FROM processes",
            "WHERE name IN ('vssadmin.exe','bcdedit.exe','wbadmin.exe','diskpart.exe')",
            "   OR cmdline LIKE '%delete shadow%' OR cmdline LIKE '%norecoveryenabled%';",
            "",
            "-- Find ransom note / encrypted file artifacts (last 1 hour)",
            "SELECT path, size, mtime FROM file",
            "WHERE (filename LIKE '%.locked' OR filename LIKE '%.encrypted' OR filename LIKE '%.crypt'",
            "       OR filename LIKE '%README%' OR filename LIKE '%DECRYPT%')",
            "  AND mtime > (strftime('%s','now') - 3600);",
            "",
            "-- VSS shadow copy status",
            "SELECT * FROM shadow_copies WHERE volume IS NOT NULL;",
        ]
    elif is_email:
        lines += [
            "-- Email client processes and suspicious child processes",
            "SELECT p.pid, p.name, p.cmdline, pp.name AS parent",
            "FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid",
            "WHERE pp.name IN ('outlook.exe','thunderbird.exe','teams.exe')",
            "  AND p.name IN ('powershell.exe','cmd.exe','wscript.exe','mshta.exe');",
            "",
            "-- Current authenticated user sessions",
            "SELECT * FROM logged_in_users;",
        ]
    elif is_auth:
        lines += [
            "-- Current user sessions and authentication state",
            "SELECT * FROM logged_in_users;",
            "",
            "-- Failed authentication artifacts (Windows event log via osquery)",
            "SELECT pid, name, cmdline FROM processes",
            "WHERE name IN ('lsass.exe','svchost.exe') ORDER BY start_time DESC LIMIT 10;",
            "",
            "-- RDP / remote desktop connections",
            "SELECT pid, name, remote_address, remote_port, state",
            "FROM process_open_sockets",
            "WHERE remote_port IN (3389, 5985, 5986) AND state = 'ESTABLISHED';",
        ]
    elif is_cloud:
        lines += [
            "-- Cloud CLI tools running on the endpoint",
            "SELECT pid, name, path, cmdline FROM processes",
            "WHERE name IN ('aws.exe','aws','gcloud.exe','gcloud','az.exe','az','kubectl.exe','kubectl');",
            "",
            "-- Cloud credential files",
            "SELECT path, size, mtime FROM file",
            "WHERE path LIKE '%/.aws/credentials'",
            "   OR path LIKE '%/.azure/accessTokens.json'",
            "   OR path LIKE '%gcloud/application_default_credentials.json';",
        ]
    elif is_exfil:
        lines += [
            "-- Large outbound connections (exfiltration from this host)",
            "SELECT p.pid, p.name, p.path, s.remote_address, s.remote_port, s.state",
            "FROM processes p JOIN process_open_sockets s ON p.pid = s.pid",
            "WHERE s.state = 'ESTABLISHED'",
            "  AND s.remote_address NOT IN ('127.0.0.1','::1')",
            "  AND p.name NOT IN ('chrome.exe','msedge.exe','firefox.exe','svchost.exe');",
            "",
            "-- Archive files that may contain staged data",
            "SELECT path, size, mtime FROM file",
            "WHERE (filename LIKE '%.zip' OR filename LIKE '%.7z' OR filename LIKE '%.rar' OR filename LIKE '%.tar.gz')",
            "  AND mtime > (strftime('%s','now') - 86400);",
        ]
    elif is_web:
        lines += [
            "-- Web server processes and suspicious child processes",
            "SELECT p.pid, p.name, p.cmdline, pp.name AS parent",
            "FROM processes p LEFT JOIN processes pp ON p.parent = pp.pid",
            "WHERE pp.name IN ('w3wp.exe','httpd','nginx','apache2','php-fpm','node','gunicorn')",
            "  AND p.name IN ('cmd.exe','powershell.exe','sh','bash','python.exe','perl.exe');",
            "",
            "-- Suspicious files in web root (web shells)",
            "SELECT path, size, mtime FROM file",
            "WHERE (path LIKE '%/wwwroot/%' OR path LIKE '%/htdocs/%' OR path LIKE '%/var/www/%')",
            "  AND (filename LIKE '%.php' OR filename LIKE '%.aspx' OR filename LIKE '%.jsp')",
            "  AND mtime > (strftime('%s','now') - 86400);",
        ]
    elif is_usb:
        lines += [
            "-- USB devices currently connected",
            "SELECT device_id, device_name, vendor_id, product_id, serial FROM usb_devices;",
            "",
            "-- Processes running from removable media",
            "SELECT pid, name, path, cmdline FROM processes",
            "WHERE path LIKE 'E:\\%' OR path LIKE 'F:\\%' OR path LIKE 'G:\\%'",
            "   OR cmdline LIKE '%autorun%' OR cmdline LIKE '%removable%';",
        ]
    elif is_lolbin:
        lines += [
            "-- LOLBin processes (living-off-the-land binaries)",
            "SELECT pid, name, path, cmdline, parent FROM processes",
            "WHERE name IN ('rundll32.exe','regsvr32.exe','mshta.exe','certutil.exe',",
            "               'bitsadmin.exe','wmic.exe','odbcconf.exe','ieexec.exe')",
            "  AND (cmdline LIKE '%http%' OR cmdline LIKE '%AppData%' OR cmdline LIKE '%Temp%');",
        ]
    elif is_supply:
        lines += [
            "-- Build/CI process activity",
            "SELECT pid, name, path, cmdline FROM processes",
            "WHERE name IN ('npm.cmd','pip.exe','pip3','mvn.exe','gradle','cargo','go')",
            "   OR path LIKE '%jenkins%' OR path LIKE '%gitlab%' OR path LIKE '%github%';",
            "",
            "-- Recently installed packages / executables",
            "SELECT path, size, mtime FROM file",
            "WHERE path LIKE '%node_modules%' OR path LIKE '%site-packages%'",
            "  AND mtime > (strftime('%s','now') - 3600);",
        ]
    elif is_container:
        lines += [
            "-- Docker containers running on this host",
            "SELECT id, image, status, state FROM docker_containers;",
            "",
            "-- Container processes that may have escaped",
            "SELECT pid, name, path, cmdline FROM processes",
            "WHERE name IN ('nsenter','chroot','unshare','runc','containerd');",
        ]
    elif is_shadow_it or is_ai_tool:
        lines += [
            "-- Unauthorised SaaS / AI tool connections",
            "SELECT p.pid, p.name, s.remote_address, s.remote_port",
            "FROM processes p JOIN process_open_sockets s ON p.pid = s.pid",
            "WHERE s.state = 'ESTABLISHED'",
            "  AND p.name NOT IN ('chrome.exe','msedge.exe','firefox.exe');",
            "",
            "-- Browser extensions that may be proxying AI tools",
            "SELECT name, path FROM chrome_extensions WHERE enabled = 1;",
        ]
    else:  # Generic
        lines += [
            "-- Generic process and connection inventory",
            "SELECT pid, name, path, cmdline FROM processes",
            "WHERE name IN ('powershell.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe')",
            "   OR (cmdline LIKE '%-enc%' OR cmdline LIKE '%base64%' OR cmdline LIKE '%DownloadString%');",
            "",
            "SELECT p.pid, p.name, s.remote_address, s.remote_port FROM processes p",
            "JOIN process_open_sockets s ON p.pid = s.pid",
            "WHERE s.state = 'ESTABLISHED' AND s.remote_address NOT IN ('127.0.0.1','::1');",
        ]

    return "\n".join(lines)


def _build_elastic(so_query: str) -> str:
    """Build Elastic KQL by adapting the Security Onion KQL (very similar, minor differences)."""
    # SO KQL and Elastic KQL are almost identical for ECS fields
    lines = ["// Elastic KQL — mirrors Security Onion query with Elastic-specific adjustments"]
    for line in so_query.split("\n"):
        if line.startswith("#"):
            lines.append("// " + line[1:].strip())
        else:
            # Minor adaptations
            adapted = (line
                       .replace("event.code:", "event.code: ")
                       .replace(":suricata.eve", ": \"suricata.eve\"")
                       .replace(":zeek.conn", ": \"zeek.conn\"")
                       .replace(":zeek.dns", ": \"zeek.dns\"")
                       .replace(":zeek.http", ": \"zeek.http\"")
                       .replace(":zeek.kerberos", ": \"zeek.kerberos\"")
                       .replace(":zeek.ntlm", ": \"zeek.ntlm\"")
                       .replace(":aws.cloudtrail", ": \"aws.cloudtrail\"")
                       .replace(":azure.activitylogs", ": \"azure.activitylogs\"")
                       )
            lines.append(adapted)
    return "\n".join(lines)


def _build_sigma(pb_name: str, step_title: str,
                 is_auth: bool, is_ransomware: bool, is_lolbin: bool,
                 is_process: bool, is_exfil: bool, is_network: bool,
                 is_email: bool, is_web: bool, is_cloud: bool) -> str:
    """Generate a Sigma YAML rule for the playbook/step."""
    safe_name = re.sub(r"[^a-zA-Z0-9 ]+", " ", pb_name).strip()[:60]
    uid = sigma_uid(f"{pb_name}-{step_title}")

    if is_ransomware:
        return (
            f"title: {safe_name} — VSS/Shadow Copy Deletion\n"
            f"id: {uid}\nstatus: stable\n"
            "description: Detects shadow copy deletion commands used in ransomware attacks.\n"
            "tags:\n    - attack.impact\n    - attack.t1490\n"
            "logsource:\n    category: process_creation\n    product: windows\n"
            "detection:\n    selection:\n"
            "        Image|endswith:\n            - '\\\\vssadmin.exe'\n            - '\\\\bcdedit.exe'\n            - '\\\\wbadmin.exe'\n"
            "        CommandLine|contains:\n            - 'delete shadows'\n            - 'norecoveryenabled'\n"
            f"    condition: selection\nfalsepositives:\n    - Authorized backup administration\ndate: {TODAY}\nlevel: critical"
        )
    elif is_email:
        return (
            f"title: {safe_name} — Phishing Office Macro Spawn\n"
            f"id: {uid}\nstatus: stable\n"
            "description: Detects Office application spawning shell — phishing payload execution.\n"
            "tags:\n    - attack.initial-access\n    - attack.t1566\n"
            "logsource:\n    category: process_creation\n    product: windows\n"
            "detection:\n    selection:\n"
            "        ParentImage|endswith:\n            - '\\\\winword.exe'\n            - '\\\\excel.exe'\n            - '\\\\outlook.exe'\n"
            "        Image|endswith:\n            - '\\\\powershell.exe'\n            - '\\\\cmd.exe'\n            - '\\\\wscript.exe'\n"
            f"    condition: selection\nfalsepositives:\n    - Legitimate macro-enabled templates\ndate: {TODAY}\nlevel: high"
        )
    elif is_auth:
        return (
            f"title: {safe_name} — Authentication Failure Burst\n"
            f"id: {uid}\nstatus: experimental\n"
            "description: Detects burst of authentication failures — indicator of brute force or credential stuffing.\n"
            "tags:\n    - attack.credential-access\n    - attack.t1110\n"
            "logsource:\n    product: windows\n    service: security\n"
            "detection:\n    selection:\n        EventID: 4625\n"
            f"    condition: selection | count() by winlog.event_data.IpAddress > 10\nfalsepositives:\n    - Misconfigured services\ndate: {TODAY}\nlevel: medium"
        )
    elif is_lolbin:
        return (
            f"title: {safe_name} — LOLBin Proxy Execution\n"
            f"id: {uid}\nstatus: stable\n"
            "description: Detects abuse of Windows LOLBins to proxy code execution.\n"
            "tags:\n    - attack.defense-evasion\n    - attack.t1218\n"
            "logsource:\n    category: process_creation\n    product: windows\n"
            "detection:\n    selection:\n"
            "        Image|endswith:\n            - '\\\\rundll32.exe'\n            - '\\\\regsvr32.exe'\n            - '\\\\mshta.exe'\n            - '\\\\certutil.exe'\n"
            "        CommandLine|contains:\n            - 'http'\n            - '\\AppData'\n            - '\\Temp'\n"
            f"    condition: selection\nfalsepositives:\n    - Legitimate use of system utilities\ndate: {TODAY}\nlevel: high"
        )
    elif is_web:
        return (
            f"title: {safe_name} — Web Server Spawning Shell\n"
            f"id: {uid}\nstatus: experimental\n"
            "description: Detects web server process spawning interactive shell — RCE or web shell execution indicator.\n"
            "tags:\n    - attack.initial-access\n    - attack.t1190\n    - attack.persistence\n    - attack.t1505_003\n"
            "logsource:\n    category: process_creation\n    product: windows\n"
            "detection:\n    selection:\n"
            "        ParentImage|endswith:\n            - '\\\\w3wp.exe'\n            - '\\\\httpd.exe'\n"
            "        Image|endswith:\n            - '\\\\cmd.exe'\n            - '\\\\powershell.exe'\n"
            f"    condition: selection\nfalsepositives:\n    - Legitimate web app build scripts\ndate: {TODAY}\nlevel: critical"
        )
    elif is_exfil:
        return (
            f"title: {safe_name} — Large Outbound Data Transfer\n"
            f"id: {uid}\nstatus: experimental\n"
            "description: Detects large outbound data transfers that may indicate exfiltration.\n"
            "tags:\n    - attack.exfiltration\n    - attack.t1041\n"
            "logsource:\n    category: network\n    product: zeek\n    service: conn\n"
            "detection:\n    selection:\n        orig_bytes|gte: 10000000\n"
            "    filter:\n        id.resp_h|cidr:\n            - '10.0.0.0/8'\n            - '172.16.0.0/12'\n"
            f"    condition: selection and not filter\nfalsepositives:\n    - Authorized cloud backup\ndate: {TODAY}\nlevel: high"
        )
    elif is_cloud:
        return (
            f"title: {safe_name} — Cloud API Failure Spike\n"
            f"id: {uid}\nstatus: experimental\n"
            "description: Detects spike in failed cloud API calls indicating credential abuse or misconfiguration.\n"
            "tags:\n    - attack.initial-access\n    - attack.t1078_004\n"
            "logsource:\n    product: aws\n    service: cloudtrail\n"
            "detection:\n    selection:\n        eventName: ConsoleLogin\n        responseElements.ConsoleLogin: Failure\n"
            f"    condition: selection | count() by sourceIPAddress > 5\nfalsepositives:\n    - Misconfigured automation\ndate: {TODAY}\nlevel: high"
        )
    else:
        return (
            f"title: {safe_name} Detection\n"
            f"id: {uid}\nstatus: experimental\n"
            f"description: Detects suspicious activity associated with {safe_name}.\n"
            "tags:\n    - attack.unknown\n"
            "logsource:\n    category: process_creation\n    product: windows\n"
            "detection:\n    selection:\n"
            "        Image|endswith:\n            - '\\\\powershell.exe'\n            - '\\\\cmd.exe'\n"
            "        CommandLine|contains:\n            - '-enc'\n            - 'DownloadString'\n            - 'IEX'\n"
            f"    condition: selection\nfalsepositives:\n    - Legitimate administrative scripts\ndate: {TODAY}\nlevel: medium"
        )


# ── Main ────────────────────────────────────────────────────────────────────────

def process_playbook(path: Path) -> bool:
    """Add missing platform queries to a single playbook. Returns True if modified."""
    pb = json.loads(path.read_text(encoding="utf-8"))

    # Detect step fields (legacy vs new schema)
    det_steps = pb.get("detSteps") or pb.get("investigation", {}).get("detectionAnalysis", [])
    if not det_steps:
        return False

    modified = False

    for i, step in enumerate(det_steps):
        new_q = generate_queries(pb, step, i)
        if new_q:
            queries = step.setdefault("queries", {})
            for platform, query in new_q.items():
                queries[platform] = query
            modified = True

    # Also handle contSteps, eradSteps, recSteps for consistency
    for section_key in ("contSteps", "eradSteps", "recSteps"):
        for step in pb.get(section_key, []):
            sq = step.setdefault("queries", {})
            if not sq:
                continue  # leave empty sections alone

    if not modified:
        return False

    # Write back with 2-space indent
    path.write_text(json.dumps(pb, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return True


def main() -> int:
    updated = 0
    skipped = 0

    for category_dir in sorted(PLAYBOOK_DIR.iterdir()):
        if not category_dir.is_dir():
            continue
        if category_dir.name in SKIP_DIRS:
            continue

        for pb_file in sorted(category_dir.glob("*.json")):
            if pb_file.name in SKIP_FILES:
                continue
            if FILE_FILTER and FILE_FILTER not in pb_file.name:
                continue
            try:
                if process_playbook(pb_file):
                    print(f"  ✓ {category_dir.name}/{pb_file.name}")
                    updated += 1
                else:
                    skipped += 1
            except Exception as exc:
                print(f"  ERROR {pb_file.name}: {exc}")

    print(f"\nPlaybooks updated: {updated} | Skipped (already complete): {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
