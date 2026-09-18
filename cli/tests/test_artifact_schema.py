import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


def test_run_artifact_schema_accepts_v1_artifact():
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas" / "run-artifact.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    artifact = {
        "schema_version": "1.0.0",
        "product_version": "1.0.0",
        "run": {
            "id": "run-test",
            "started_at": "2026-09-18T10:00:00Z",
            "completed_at": "2026-09-18T10:00:01Z",
            "mode": "active",
            "scope": ["192.168.1.19/32"],
            "exclude": [],
        },
        "coverage": {
            "attempted_ipv4": 1,
            "responsive": 1,
            "neighbor_cache": 0,
            "managed_sources": 0,
            "methods": ["local_interface", "neighbor_cache", "icmp_echo"],
            "issues": [],
            "statement": "Cobertura acotada.",
        },
        "assets": [{"id": "local:test", "kind": "device"}],
        "relationships": [],
        "services": [],
        "findings": [],
    }
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(artifact)
