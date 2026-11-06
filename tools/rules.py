"""Shared loading helpers for the detection library tools."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"
ATTACK_FILE = Path(__file__).resolve().parent / "attack_techniques.json"


def rule_files(directory: Path = DETECTIONS_DIR) -> list[Path]:
    return sorted(p for p in directory.rglob("*.yaml") if p.is_file())


def load_rule(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError("file does not contain a YAML mapping")
    return data


def load_attack(path: Path = ATTACK_FILE) -> dict[str, dict]:
    return json.loads(path.read_text(encoding="utf-8"))["techniques"]
