"""Validate every detection rule before it reaches Sentinel.

Checks the Sentinel scheduled-rule schema (fields, enums, query frequency and
period limits, entity mappings), library conventions (false positives and a
test method on every rule), ATT&CK consistency, and basic KQL hygiene.

    python tools/validate.py            # validate detections/
    python tools/validate.py some.yaml  # validate specific files
"""

from __future__ import annotations

import re
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rules import load_attack, load_rule, rule_files  # noqa: E402

REQUIRED_FIELDS = [
    "id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
    "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
    "query", "entityMappings", "version", "kind",
]
LIBRARY_FIELDS = ["falsePositives", "testing"]  # this library's conventions

SEVERITIES = {"Informational", "Low", "Medium", "High"}
TRIGGER_OPERATORS = {"gt", "lt", "eq"}
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
    "Collection", "CommandAndControl", "Exfiltration", "Impact",
}
ENTITY_IDENTIFIERS = {
    "Account": {"FullName", "Name", "NTDomain", "UPNSuffix", "Sid", "AadUserId", "ObjectGuid", "DnsDomain"},
    "Host": {"FullName", "HostName", "DnsDomain", "NetBiosName", "AzureID", "OMSAgentID", "OSFamily"},
    "IP": {"Address"},
    "URL": {"Url"},
    "FileHash": {"Algorithm", "Value"},
    "File": {"Name", "Directory"},
    "Process": {"ProcessId", "CommandLine", "CreationTimeUtc"},
    "RegistryKey": {"Hive", "Key"},
    "DNS": {"DomainName"},
    "Mailbox": {"MailboxPrimaryAddress", "DisplayName", "Upn"},
}
MAX_ENTITY_MAPPINGS = 10
MAX_FIELD_MAPPINGS = 3
MIN_DURATION = timedelta(minutes=5)
MAX_DURATION = timedelta(days=14)

GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DURATION_RE = re.compile(r"^(\d+)([mhd])$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
FORBIDDEN_QUERY_PATTERNS = {
    r"\bsearch\s+\*": "'search *' scans every table; query the tables you need",
    r"\bunion\s+\*": "'union *' scans every table; name the tables explicitly",
}


def parse_duration(value: object) -> timedelta | None:
    match = DURATION_RE.match(str(value))
    if not match:
        return None
    amount, unit = int(match.group(1)), match.group(2)
    return {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]


def strip_kql_strings_and_comments(query: str) -> str:
    """Return the query with string literals and // comments removed.

    A single left-to-right scan, because the two interact: '//' inside a
    string ("https://...") is not a comment, and a quote inside a comment is
    not a string. Handles "..." and '...' with backslash escapes, and verbatim
    @"..." / @'...' strings where the quote is escaped by doubling it.
    """
    out: list[str] = []
    i, n = 0, len(query)
    while i < n:
        ch = query[i]
        if ch == "/" and query.startswith("//", i):
            while i < n and query[i] != "\n":
                i += 1
            continue
        verbatim = ch == "@" and i + 1 < n and query[i + 1] in "\"'"
        if verbatim or ch in "\"'":
            quote = query[i + 1] if verbatim else ch
            i += 2 if verbatim else 1
            while i < n:
                if verbatim and query[i] == quote:
                    if i + 1 < n and query[i + 1] == quote:  # doubled quote = escaped
                        i += 2
                        continue
                    break
                if not verbatim and query[i] == "\\":
                    i += 2
                    continue
                if not verbatim and query[i] == quote:
                    break
                i += 1
            i += 1  # closing quote
            out.append('""')
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def brackets_balanced(query: str) -> bool:
    pairs, stack = {")": "(", "]": "[", "}": "{"}, []
    for ch in strip_kql_strings_and_comments(query):
        if ch in "([{":
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack.pop() != pairs[ch]:
                return False
    return not stack


def validate_rule(rule: dict, attack: dict[str, dict]) -> list[str]:
    errors: list[str] = []

    for field in REQUIRED_FIELDS + LIBRARY_FIELDS:
        if field not in rule or rule[field] in (None, "", []):
            errors.append(f"missing required field '{field}'")
    if errors:
        return errors  # the remaining checks assume the fields exist

    if not GUID_RE.match(str(rule["id"]).lower()):
        errors.append(f"id '{rule['id']}' is not a GUID")
    if len(str(rule["name"])) > 100:
        errors.append("name is longer than 100 characters")
    if rule["severity"] not in SEVERITIES:
        errors.append(f"severity '{rule['severity']}' must be one of {sorted(SEVERITIES)}")
    if rule["kind"] != "Scheduled":
        errors.append("kind must be 'Scheduled'")
    if not SEMVER_RE.match(str(rule["version"])):
        errors.append(f"version '{rule['version']}' must look like 1.0.0")
    if rule["triggerOperator"] not in TRIGGER_OPERATORS:
        errors.append(f"triggerOperator must be one of {sorted(TRIGGER_OPERATORS)}")
    if not isinstance(rule["triggerThreshold"], int) or rule["triggerThreshold"] < 0:
        errors.append("triggerThreshold must be a non-negative integer")

    frequency, period = parse_duration(rule["queryFrequency"]), parse_duration(rule["queryPeriod"])
    for name, value in (("queryFrequency", frequency), ("queryPeriod", period)):
        if value is None:
            errors.append(f"{name} '{rule[name]}' must look like 5m, 1h or 1d")
        elif not MIN_DURATION <= value <= MAX_DURATION:
            errors.append(f"{name} must be between 5m and 14d (Sentinel limit)")
    if frequency and period and period < frequency:
        errors.append("queryPeriod is shorter than queryFrequency: events between runs would be missed")

    query = str(rule["query"])
    errors += _check_attack(rule, attack)
    errors += _check_connectors(rule, query)
    errors += _check_entities(rule, query)
    if not brackets_balanced(query):
        errors.append("query has unbalanced brackets")
    for pattern, message in FORBIDDEN_QUERY_PATTERNS.items():
        if re.search(pattern, query, re.IGNORECASE):
            errors.append(message)

    if not all(isinstance(item, str) and item.strip() for item in rule["falsePositives"]):
        errors.append("falsePositives must be a list of non-empty strings")
    if not all(isinstance(item, str) and item.strip() for item in rule["testing"]):
        errors.append("testing must be a list of non-empty strings")
    return errors


def _check_attack(rule: dict, attack: dict[str, dict]) -> list[str]:
    errors = []
    tactics = set(rule["tactics"])
    for tactic in tactics - TACTICS:
        errors.append(f"unknown tactic '{tactic}'")
    covered: set[str] = set()
    for technique in rule["relevantTechniques"]:
        if not TECHNIQUE_RE.match(str(technique)):
            errors.append(f"technique '{technique}' must look like T1234 or T1234.001")
            continue
        if technique not in attack:
            errors.append(f"technique '{technique}' is not in tools/attack_techniques.json")
            continue
        technique_tactics = set(attack[technique]["tactics"])
        if not technique_tactics & tactics:
            errors.append(f"technique {technique} belongs to {sorted(technique_tactics)}, "
                          f"none of which is in tactics {sorted(tactics)}")
        covered |= technique_tactics
    for tactic in sorted(tactics & TACTICS - covered):
        if covered:
            errors.append(f"tactic '{tactic}' is not supported by any listed technique")
    return errors


def _check_connectors(rule: dict, query: str) -> list[str]:
    errors = []
    for connector in rule["requiredDataConnectors"]:
        if not isinstance(connector, dict) or not connector.get("connectorId") or not connector.get("dataTypes"):
            errors.append("each requiredDataConnectors entry needs connectorId and dataTypes")
            continue
        for table in connector["dataTypes"]:
            if not re.search(rf"\b{re.escape(str(table))}\b", query):
                errors.append(f"data type '{table}' is declared but never used in the query")
    return errors


def _check_entities(rule: dict, query: str) -> list[str]:
    errors = []
    mappings = rule["entityMappings"]
    if len(mappings) > MAX_ENTITY_MAPPINGS:
        errors.append(f"more than {MAX_ENTITY_MAPPINGS} entity mappings")
    for mapping in mappings:
        entity = mapping.get("entityType")
        if entity not in ENTITY_IDENTIFIERS:
            errors.append(f"unknown entityType '{entity}'")
            continue
        fields = mapping.get("fieldMappings") or []
        if not 1 <= len(fields) <= MAX_FIELD_MAPPINGS:
            errors.append(f"{entity}: needs 1-{MAX_FIELD_MAPPINGS} fieldMappings")
        for field in fields:
            identifier, column = field.get("identifier"), field.get("columnName")
            if identifier not in ENTITY_IDENTIFIERS[entity]:
                errors.append(f"{entity}: identifier '{identifier}' is not valid for this entity")
            if not column or not re.search(rf"\b{re.escape(str(column))}\b", query):
                errors.append(f"{entity}: column '{column}' is not produced by the query")
    return errors


def validate_paths(paths: list[Path]) -> dict[Path, list[str]]:
    attack = load_attack()
    results: dict[Path, list[str]] = {}
    seen_ids: dict[str, Path] = {}
    seen_names: dict[str, Path] = {}
    for path in paths:
        try:
            rule = load_rule(path)
        except Exception as exc:  # YAML errors, wrong top-level type
            results[path] = [f"cannot parse: {exc}"]
            continue
        errors = validate_rule(rule, attack)
        rule_id, name = str(rule.get("id", "")).lower(), str(rule.get("name", ""))
        if rule_id and rule_id in seen_ids:
            errors.append(f"duplicate id (also in {seen_ids[rule_id].name})")
        if name and name in seen_names:
            errors.append(f"duplicate name (also in {seen_names[name].name})")
        seen_ids.setdefault(rule_id, path)
        seen_names.setdefault(name, path)
        results[path] = errors
    return results


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    paths = [Path(a) for a in argv] if argv else rule_files()
    if not paths:
        print("no rules found")
        return 1
    results = validate_paths(paths)
    failed = {p: e for p, e in results.items() if e}
    for path, errors in failed.items():
        for error in errors:
            print(f"FAIL {path}: {error}")
    print(f"{len(results) - len(failed)}/{len(results)} rules valid")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
