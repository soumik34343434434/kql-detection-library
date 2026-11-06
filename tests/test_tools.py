import copy
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import coverage  # noqa: E402
import export_arm  # noqa: E402
import validate  # noqa: E402
from rules import load_attack, load_rule, rule_files  # noqa: E402

ATTACK = load_attack()
BASE_RULE = load_rule(ROOT / "detections" / "credential_access" / "brute_force_then_success.yaml")


def errors_for(**changes):
    rule = copy.deepcopy(BASE_RULE)
    for key, value in changes.items():
        if value is None:
            rule.pop(key, None)
        else:
            rule[key] = value
    return validate.validate_rule(rule, ATTACK)


class LibraryTests(unittest.TestCase):
    def test_every_shipped_rule_is_valid(self):
        results = validate.validate_paths(rule_files())
        self.assertGreaterEqual(len(results), 12)
        self.assertEqual({p.name: e for p, e in results.items() if e}, {})

    def test_every_technique_in_rules_is_known(self):
        for path in rule_files():
            for technique in load_rule(path)["relevantTechniques"]:
                self.assertIn(technique, ATTACK, path.name)


class ValidatorTests(unittest.TestCase):
    def assertError(self, errors, fragment):
        self.assertTrue(any(fragment in e for e in errors), f"expected '{fragment}' in {errors}")

    def test_base_rule_is_valid(self):
        self.assertEqual(errors_for(), [])

    def test_missing_fields(self):
        self.assertError(errors_for(query=None), "missing required field 'query'")
        self.assertError(errors_for(falsePositives=None), "missing required field 'falsePositives'")

    def test_bad_id_severity_and_kind(self):
        self.assertError(errors_for(id="not-a-guid"), "is not a GUID")
        self.assertError(errors_for(severity="Critical"), "severity 'Critical'")
        self.assertError(errors_for(kind="NRT"), "kind must be 'Scheduled'")

    def test_schedule_limits(self):
        self.assertError(errors_for(queryFrequency="1m"), "between 5m and 14d")
        self.assertError(errors_for(queryPeriod="30d"), "between 5m and 14d")
        self.assertError(errors_for(queryFrequency="2h", queryPeriod="1h"), "shorter than queryFrequency")
        self.assertError(errors_for(queryFrequency="hourly"), "must look like 5m")

    def test_attack_consistency(self):
        self.assertError(errors_for(relevantTechniques=["T9999"]), "not in tools/attack_techniques.json")
        self.assertError(errors_for(relevantTechniques=["T1566.002"]), "none of which is in tactics")
        self.assertError(errors_for(tactics=["CredentialAccess", "Impact"]), "tactic 'Impact' is not supported")
        self.assertError(errors_for(tactics=["Hacking"]), "unknown tactic 'Hacking'")

    def test_connectors_must_be_used(self):
        connectors = [{"connectorId": "MicrosoftThreatProtection", "dataTypes": ["DeviceProcessEvents"]}]
        self.assertError(errors_for(requiredDataConnectors=connectors), "'DeviceProcessEvents' is declared but never used")

    def test_entity_columns_and_identifiers(self):
        mappings = [{"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "NoSuchColumn"}]}]
        self.assertError(errors_for(entityMappings=mappings), "column 'NoSuchColumn' is not produced")
        mappings = [{"entityType": "Host", "fieldMappings": [{"identifier": "Url", "columnName": "Computer"}]}]
        self.assertError(errors_for(entityMappings=mappings), "identifier 'Url' is not valid")

    def test_query_hygiene(self):
        self.assertError(errors_for(query="search * | where x == 1"), "'search *' scans every table")
        self.assertError(errors_for(query="SecurityEvent | where (EventID == 4625"), "unbalanced brackets")

    def test_duplicate_ids_across_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = (ROOT / "detections" / "credential_access" / "brute_force_then_success.yaml").read_text()
            first, second = pathlib.Path(tmp, "a.yaml"), pathlib.Path(tmp, "b.yaml")
            first.write_text(source)
            second.write_text(source.replace("name: Successful logon", "name: Copy of successful logon"))
            results = validate.validate_paths([first, second])
            self.assertTrue(any("duplicate id" in e for e in results[second]))


class KqlScannerTests(unittest.TestCase):
    def test_urls_in_strings_are_not_comments(self):
        query = 'T | extend u = extract(@"(https?://[^\\s\'""]+)", 1, x) // note (unbalanced in comment'
        self.assertTrue(validate.brackets_balanced(query))

    def test_quotes_inside_comments_are_ignored(self):
        self.assertTrue(validate.brackets_balanced("T // don't count this (\n| where (a == 'b')"))

    def test_unbalanced_detected(self):
        self.assertFalse(validate.brackets_balanced("T | where (a == 1"))
        self.assertFalse(validate.brackets_balanced("T | where a in (1, 2]"))


class CoverageTests(unittest.TestCase):
    def test_layer_counts_rules_per_technique(self):
        rules = coverage.collect()
        layer = coverage.build_layer(rules, ATTACK)
        ids = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIn("T1059.001", ids)
        self.assertEqual(sum(ids.values()), sum(len(r["relevantTechniques"]) for r in rules))

    def test_committed_coverage_is_current(self):
        self.assertEqual(coverage.main(["--check"]), 0)


class ExportTests(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(export_arm.iso_duration("30m"), "PT30M")
        self.assertEqual(export_arm.iso_duration("1h"), "PT1H")
        self.assertEqual(export_arm.iso_duration("1d"), "P1D")
        with self.assertRaises(ValueError):
            export_arm.iso_duration("1w")

    def test_template_shape(self):
        rules = [load_rule(p) for p in rule_files()]
        template = export_arm.build_template(rules)
        self.assertEqual(len(template["resources"]), len(rules))
        props = {r["properties"]["displayName"]: r["properties"] for r in template["resources"]}
        brute = props[BASE_RULE["name"]]
        self.assertEqual(brute["triggerOperator"], "GreaterThan")
        self.assertEqual(brute["techniques"], ["T1110"])  # parent IDs only
        self.assertEqual(brute["queryPeriod"], "PT1H")
        json.dumps(template)  # serialisable


if __name__ == "__main__":
    unittest.main()
