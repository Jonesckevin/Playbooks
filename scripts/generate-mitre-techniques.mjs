import fs from "node:fs/promises";
import path from "node:path";

const SOURCES = [
  ["enterprise", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"],
  ["mobile", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"],
  ["ics", "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"]
];

const idRegex = /^T\d{4}(?:\.\d{3})?$/;

function fallbackUrl(id) {
  const [technique, subTechnique] = id.split(".");
  if (subTechnique) {
    return `https://attack.mitre.org/techniques/${technique}/${subTechnique}/`;
  }
  return `https://attack.mitre.org/techniques/${technique}/`;
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} for ${url}`);
  }
  return response.json();
}

function normalizeTechnique(raw, domain, bucket) {
  if (raw.type !== "attack-pattern" || raw.revoked || raw.x_mitre_deprecated) {
    return;
  }

  const refs = Array.isArray(raw.external_references) ? raw.external_references : [];
  const mitreRef = refs.find((r) => typeof r.external_id === "string" && idRegex.test(r.external_id));
  if (!mitreRef) return;

  const id = mitreRef.external_id.toUpperCase();
  const current = bucket.get(id) || {
    id,
    name: raw.name || id,
    url: mitreRef.url || fallbackUrl(id),
    domains: [],
    tactics: [],
    isSubtechnique: false
  };

  if (raw.name && (!current.name || current.name === id)) {
    current.name = raw.name;
  }

  if (!current.url) {
    current.url = mitreRef.url || fallbackUrl(id);
  }

  if (!current.domains.includes(domain)) {
    current.domains.push(domain);
  }

  if (raw.x_mitre_is_subtechnique) {
    current.isSubtechnique = true;
  }

  const phases = Array.isArray(raw.kill_chain_phases) ? raw.kill_chain_phases : [];
  for (const phase of phases) {
    const name = phase?.phase_name ? String(phase.phase_name) : "";
    if (name && !current.tactics.includes(name)) {
      current.tactics.push(name);
    }
  }

  bucket.set(id, current);
}

async function main() {
  const outputPathArg = process.argv[2] || path.join("app", "playbooks", "mitre-techniques.json");
  const outputPath = path.resolve(outputPathArg);
  const techniques = new Map();
  const domains = {};

  for (const [domain, url] of SOURCES) {
    const payload = await fetchJson(url);
    const objects = Array.isArray(payload.objects) ? payload.objects : [];
    domains[domain] = { url, objects: objects.length };

    for (const obj of objects) {
      normalizeTechnique(obj, domain, techniques);
    }
  }

  const sorted = [...techniques.keys()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const data = {
    generatedAt: new Date().toISOString(),
    source: "mitre-attack/attack-stix-data",
    domains,
    count: sorted.length,
    techniques: sorted.map((id) => techniques.get(id))
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");

  console.log(`Wrote ${outputPath} with ${data.count} techniques`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
