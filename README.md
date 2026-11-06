# kql-detection-library

[![CI](https://github.com/soumik34343434434/kql-detection-library/actions/workflows/ci.yml/badge.svg)](https://github.com/soumik34343434434/kql-detection-library/actions/workflows/ci.yml)

**Detection-as-code for Microsoft Sentinel and Defender XDR.**
- **Rules:** 12 KQL analytics rules, each mapped to MITRE ATT&CK, with documented false positives and a way to test them.
- **Checks:** a Python validator catches broken rules before they reach a workspace.
- **Coverage:** a generator produces an ATT&CK Navigator layer.
- **Deployment:** an exporter turns the library into one ARM template.

**12 rules · 15 ATT&CK techniques · 8 tactics** → [full coverage table](coverage/COVERAGE.md)

## Why detection-as-code

In many SOCs, analytics rules are edited by hand in the portal:
- there is no review and no history;
- nobody can say which ATT&CK techniques are covered.

Here every rule is a YAML file in Git, so changes are reviewed in pull requests and checked by CI. Coverage is regenerated from the rules themselves, so it can't drift.

## The rules

| Tactic | Rule | ATT&CK | Data |
|---|---|---|---|
| Initial Access | [Malicious attachment reached a mailbox](detections/initial_access/malicious_attachment_delivered.yaml) | T1566.001 | EmailAttachmentInfo, EmailEvents |
| Initial Access | [User clicked a URL later flagged as phishing](detections/initial_access/phishing_url_clicked.yaml) | T1566.002, T1204.001 | UrlClickEvents, EmailEvents |
| Execution | [PowerShell launched with an encoded command](detections/execution/encoded_powershell.yaml) (decodes the payload in the query) | T1059.001, T1027 | DeviceProcessEvents |
| Persistence | [Scheduled task with a script host or user-writable path](detections/persistence/scheduled_task_suspicious_command.yaml) | T1053.005 | DeviceProcessEvents |
| Persistence | [Registry Run key pointing to a script host or user-writable path](detections/persistence/registry_run_key_persistence.yaml) | T1547.001 | DeviceRegistryEvents |
| Persistence | [Local account created and added to Administrators within 1 hour](detections/persistence/new_local_admin_account.yaml) | T1136.001, T1098 | SecurityEvent |
| Defense Evasion | [Microsoft Defender protection disabled or excluded](detections/defense_evasion/defender_tampering.yaml) | T1562.001 | DeviceProcessEvents |
| Defense Evasion | [Windows Security event log cleared](detections/defense_evasion/security_log_cleared.yaml) | T1070.001 | SecurityEvent |
| Credential Access | [Successful logon after repeated failures from the same IP](detections/credential_access/brute_force_then_success.yaml) | T1110.001 | SecurityEvent |
| Credential Access | [LSASS memory dump attempt](detections/credential_access/lsass_memory_dump.yaml) | T1003.001 | DeviceProcessEvents |
| Command and Control | [File download with a built-in Windows tool](detections/command_and_control/lolbin_file_download.yaml) | T1105 | DeviceProcessEvents |
| Impact | [Shadow copies or backups deleted (ransomware precursor)](detections/impact/shadow_copy_deletion.yaml) | T1490 | DeviceProcessEvents |

A few design choices worth noting:
- **Brute force:** it alerts on *failures followed by a success* from the same IP. That is the moment guessing becomes access, and it is much quieter than a raw failed-logon threshold.
- **Encoded PowerShell:** the rule decodes the UTF-16LE `-EncodedCommand` payload inside KQL, so analysts read the real command without running it.
- **Email rules:** they join back to `EmailEvents` and output the `NetworkMessageId`, so the same alert drives the purge.

## Rule format

Rules use the same YAML schema as Microsoft's [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) content (`id`, `name`, `severity`, `requiredDataConnectors`, `queryFrequency`, `queryPeriod`, `tactics`, `relevantTechniques`, `query`, `entityMappings` ...). This library adds two required fields:

```yaml
falsePositives:
  - Vulnerability scanners with stale credentials; exclude their source IPs.
testing:
  - "Atomic Red Team: Invoke-AtomicTest T1110.001 on a lab VM."
```

The point is that **no rule ships without saying how it fails and how to prove it works.**

## Validation (`tools/validate.py`)

Run on every push and pull request. A rule fails if:

| Check | Catches |
|---|---|
| Schema | Missing fields, non-GUID `id`, bad `severity`/`kind`/`triggerOperator`, non-semver `version` |
| Schedule | `queryFrequency`/`queryPeriod` outside Sentinel's 5m-14d limits, or a look-back shorter than the run interval (events between runs would be missed) |
| ATT&CK | Malformed technique IDs, techniques not in `tools/attack_techniques.json`, a technique that doesn't belong to any of the rule's tactics, a tactic no technique supports |
| Data sources | A table declared in `requiredDataConnectors` that the query never uses |
| Entities | Unknown entity types or identifiers, and **entity columns the query doesn't produce** (a common reason incidents arrive with no entities) |
| KQL hygiene | Unbalanced brackets (string- and comment-aware scanner), `search *` / `union *` |
| Library | Duplicate ids or names, missing `falsePositives` or `testing` |

```bash
pip install -r requirements.txt
python tools/validate.py
# 12/12 rules valid
```

## Coverage (`tools/coverage.py`)

This regenerates [`coverage/COVERAGE.md`](coverage/COVERAGE.md) and [`coverage/attack-navigator-layer.json`](coverage/attack-navigator-layer.json).

To view the layer, open the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) and choose *Open Existing Layer*, then *Upload from local*. Each technique is shaded by the number of rules covering it.

CI runs `coverage.py --check`, so the committed coverage can never go stale.

## Deploying (`tools/export_arm.py`)

```bash
python tools/export_arm.py
az deployment group create -g <resource-group> \
  --template-file build/sentinel-analytics-rules.json \
  --parameters workspace=<workspace-name>
```

The exporter does four things:
- builds one ARM template with an `alertRules` resource per rule, in the same shape Microsoft's Sentinel content templates use;
- converts durations to ISO 8601 (`1h` → `PT1H`);
- maps operators (`gt` → `GreaterThan`);
- reduces sub-techniques to the parent IDs that the `techniques` property accepts.

CI uploads the template as a build artifact.

## Status and limitations

- **Statically validated, not yet run on live data.** The queries are written against Microsoft's documented table schemas, and every rule passes the validator, but none has run in a workspace yet. I'm running them in my Sentinel home lab with Atomic Red Team, and each rule's `testing` field is the plan. Expect threshold and exclusion tuning once they meet real data.
- **The validator is not a KQL compiler.** It checks structure and conventions; a syntax error inside a valid-looking query is only caught when Sentinel parses it.
- **The ATT&CK list is a subset.** `tools/attack_techniques.json` lists only the techniques used here. Add an entry before using a new one.

## Adding a rule

1. Copy an existing rule into the right `detections/<tactic>/` folder and give it a new GUID (`python -c "import uuid; print(uuid.uuid4())"`).
2. Write the query, entity mappings, `falsePositives` and `testing`.
3. Run `python tools/validate.py && python tools/coverage.py && python -m unittest discover -s tests`.
4. Open a pull request. CI repeats the checks.

## How it was built

I designed and reviewed this library, and wrote it with help from **Claude Code** (Anthropic's AI coding assistant). The rule choices reflect what I investigate as a SOC analyst: Defender endpoint alerts, phishing, and application-control events.

## License

MIT
