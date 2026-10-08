from dataclasses import asdict, dataclass, field
import hashlib
import json


SEVERITIES = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1, "INFORMATIONAL": 0}


@dataclass
class Finding:
    source: str
    category: str
    rule: str
    severity: str
    original_severity: str
    title: str
    evidence: str
    recommendation: str
    reference: str
    locations: list[dict]
    package: str = ""
    installed_version: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self):
        self.severity = self.severity.upper()
        if self.severity not in SEVERITIES:
            raise ValueError("Severidade desconhecida no formato do scanner.")
        identity = [self.source, self.category, self.rule, self.package, self.installed_version]
        self.id = hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:16]


def group_findings(findings: list[Finding]) -> list[dict]:
    grouped = {}
    for finding in findings:
        item = asdict(finding)
        if item["id"] not in grouped:
            grouped[item["id"]] = item
            continue
        previous = grouped[item["id"]]
        for location in item["locations"]:
            if location not in previous["locations"]:
                previous["locations"].append(location)
        if SEVERITIES[item["severity"]] > SEVERITIES[previous["severity"]]:
            previous["severity"] = item["severity"]
            previous["original_severity"] = item["original_severity"]
        previous["fixed_versions"] = sorted(set(previous["fixed_versions"] + item["fixed_versions"]))
    return sorted(grouped.values(), key=lambda f: (-SEVERITIES[f["severity"]], f["rule"], f["id"]))


def redact(value, secrets: set[str]):
    if isinstance(value, str):
        for secret in sorted(secrets, key=len, reverse=True):
            if secret:
                value = value.replace(secret, "[SEGREDO REMOVIDO]")
        # Remove caracteres de controle que poderiam manipular o terminal.
        return "".join(c for c in value if c in "\n\t" or (ord(c) >= 32 and ord(c) != 127))
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, dict):
        return {redact(key, secrets): redact(item, secrets) for key, item in value.items()}
    return value
