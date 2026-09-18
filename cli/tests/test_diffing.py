from netra.diffing import compare_artifacts


def artifact(run_id, assets, services=None, relationships=None):
    return {
        "schema_version": "1.0.0",
        "run": {"id": run_id},
        "assets": assets,
        "services": services or [],
        "relationships": relationships or [],
    }


def test_diff_ignores_evidence_timestamps_and_tracks_asset_change():
    before = artifact(
        "before",
        [{"id": "old-id", "kind": "device", "addresses": ["192.168.1.5"], "macs": ["AA:BB:CC:DD:EE:FF"], "roles": ["unknown"], "evidence": [{"observed_at": "2026-01-01T00:00:00Z"}]}],
    )
    after = artifact(
        "after",
        [{"id": "old-id", "kind": "device", "addresses": ["192.168.1.5"], "macs": ["aa:bb:cc:dd:ee:ff"], "roles": ["printer"], "evidence": [{"observed_at": "2026-01-02T00:00:00Z"}]}],
    )

    result = compare_artifacts(before, after)

    assert result["summary"]["assets_added"] == 0
    assert result["summary"]["assets_removed"] == 0
    assert result["summary"]["assets_changed"] == 1
    assert result["assets"]["changed"][0]["after"]["roles"] == ["printer"]


def test_diff_tracks_services_and_relationships():
    before = artifact("before", [{"id": "a", "kind": "device", "addresses": ["192.168.1.2"]}])
    after = artifact(
        "after",
        [{"id": "a", "kind": "device", "addresses": ["192.168.1.2"]}],
        services=[{"asset_id": "a", "address": "192.168.1.2", "port": 443, "transport": "tcp", "state": "open"}],
        relationships=[{"type": "reachable_via", "state": "observed", "from": "a", "to": "b"}],
    )

    result = compare_artifacts(before, after)

    assert result["summary"]["services_added"] == 1
    assert result["summary"]["relationships_added"] == 1
