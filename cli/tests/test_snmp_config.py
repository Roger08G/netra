import json

import pytest

from netra.cli import _load_snmp_config
from netra.engine import _engine_environment


def test_snmp_config_resolves_environment_without_persisting_names(tmp_path, monkeypatch):
    path = tmp_path / "snmp.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "targets": [
                    {
                        "address": "192.168.1.2",
                        "username": "netra-ro",
                        "auth_passphrase_env": "NETRA_SNMP_TEST_AUTH",
                        "privacy_passphrase_env": "NETRA_SNMP_TEST_PRIV",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("NETRA_SNMP_TEST_AUTH", "auth-secret-value")
    monkeypatch.setenv("NETRA_SNMP_TEST_PRIV", "privacy-secret-value")
    resolved = _load_snmp_config(path)
    target = resolved["targets"][0]
    assert target["auth_passphrase"] == "auth-secret-value"
    assert target["privacy_passphrase"] == "privacy-secret-value"
    assert "auth_passphrase_env" not in target
    assert "privacy_passphrase_env" not in target


def test_snmp_config_rejects_direct_secrets(tmp_path):
    path = tmp_path / "snmp.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "targets": [
                    {
                        "address": "192.168.1.2",
                        "auth_passphrase": "do-not-store-this",
                        "privacy_passphrase_env": "NETRA_SNMP_TEST_PRIV",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="secreto directo"):
        _load_snmp_config(path)


def test_engine_environment_does_not_inherit_snmp_secrets(monkeypatch):
    monkeypatch.setenv("NETRA_SNMP_TEST_AUTH", "auth-secret-value")
    monkeypatch.setenv("UNRELATED_SETTING", "preserved")
    environment = _engine_environment()
    assert "NETRA_SNMP_TEST_AUTH" not in environment
    assert environment["UNRELATED_SETTING"] == "preserved"
