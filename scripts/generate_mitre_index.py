#!/usr/bin/env python3
"""Generate mitre-index.json from existing technique playbook files."""

import json
import os
from pathlib import Path

# Support both local development and container execution
if os.path.exists("/var/www/localhost/htdocs"):
    # Running in Docker container
    HTDOCS = Path("/var/www/localhost/htdocs")
else:
    # Running locally
    ROOT = Path(__file__).resolve().parents[1]
    HTDOCS = ROOT / "app"

TECHNIQUES_DIR = HTDOCS / "playbooks" / "techniques"
OUTPUT_FILE = HTDOCS / "playbooks-main" / "mitre-index.json"

def main():
    techniques = []
    
    if not TECHNIQUES_DIR.exists():
        print(f"Techniques directory not found: {TECHNIQUES_DIR}")
        return 1
    
    # Scan all technique JSON files
    for tech_file in sorted(TECHNIQUES_DIR.glob("*.json")):
        try:
            with open(tech_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Extract minimal metadata
            tech_entry = {
                "id": data.get("id", "unknown"),
                "name": data.get("name", ""),
                "url": data.get("mitreUrl", f"https://attack.mitre.org/techniques/{data.get('mitre', 'unknown')}"),
                "domains": data.get("domains", [data.get("domain", "enterprise")]) if isinstance(data.get("domains"), list) else [data.get("domain", "enterprise")]
            }
            techniques.append(tech_entry)
        except Exception as e:
            print(f"Error processing {tech_file}: {e}")
            continue
    
    # Write index
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump({"techniques": techniques}, f, ensure_ascii=False, indent=2)
        f.write("\n")
    
    print(f"Generated mitre-index.json with {len(techniques)} techniques")
    print(f"Output: {OUTPUT_FILE}")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
