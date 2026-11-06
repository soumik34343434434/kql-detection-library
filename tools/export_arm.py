"""Export the rules as one ARM template for deployment to a Sentinel workspace.

    python tools/export_arm.py                 # writes build/sentinel-analytics-rules.json
    az deployment group create -g <rg> \
        --template-file build/sentinel-analytics-rules.json \
        --parameters workspace=<log-analytics-workspace-name>

Uses the same resource shape as Microsoft's Sentinel content templates
(Microsoft.OperationalInsights/workspaces/providers/alertRules). Rules are
created enabled; set ENABLED = False to import them disabled for review.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rules import ROOT, load_rule, rule_files  # noqa: E402

API_VERSION = "2023-02-01"
ENABLED = True
OUTPUT = ROOT / "build" / "sentinel-analytics-rules.json"
OPERATORS = {"gt": "GreaterThan", "lt": "LessThan", "eq": "Equal"}


def iso_duration(value: str) -> str:
    """'30m' -> 'PT30M', '1h' -> 'PT1H', '1d' -> 'P1D'."""
    match = re.fullmatch(r"(\d+)([mhd])", value)
    if not match:
        raise ValueError(f"bad duration {value!r}")
    amount, unit = match.groups()
    return f"P{amount}D" if unit == "d" else f"PT{amount}{unit.upper()}"


def to_resource(rule: dict) -> dict:
    # The alertRules 'techniques' property takes parent technique IDs only.
    techniques = sorted({t.split(".")[0] for t in rule["relevantTechniques"]})
    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": API_VERSION,
        "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '{rule['id']}')]",
        "kind": "Scheduled",
        "properties": {
            "displayName": rule["name"],
            "description": rule["description"].strip(),
            "severity": rule["severity"],
            "enabled": ENABLED,
            "query": rule["query"],
            "queryFrequency": iso_duration(rule["queryFrequency"]),
            "queryPeriod": iso_duration(rule["queryPeriod"]),
            "triggerOperator": OPERATORS[rule["triggerOperator"]],
            "triggerThreshold": rule["triggerThreshold"],
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": rule["tactics"],
            "techniques": techniques,
            "entityMappings": rule["entityMappings"],
        },
    }


def build_template(rules: list[dict]) -> dict:
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {"type": "string", "metadata": {"description": "Log Analytics workspace with Microsoft Sentinel"}}
        },
        "resources": [to_resource(rule) for rule in sorted(rules, key=lambda r: r["name"])],
    }


def main(argv: list[str] | None = None) -> int:
    rules = [load_rule(path) for path in rule_files()]
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(build_template(rules), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(rules)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
