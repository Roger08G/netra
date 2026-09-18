from __future__ import annotations

from typing import Any


def compare_artifacts(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before_assets = {_asset_key(item): item for item in before.get("assets", [])}
    after_assets = {_asset_key(item): item for item in after.get("assets", [])}

    added_keys = sorted(after_assets.keys() - before_assets.keys())
    removed_keys = sorted(before_assets.keys() - after_assets.keys())
    common_keys = sorted(before_assets.keys() & after_assets.keys())
    changed = []
    for key in common_keys:
        old = _asset_view(before_assets[key])
        new = _asset_view(after_assets[key])
        if old != new:
            changed.append({"key": key, "before": old, "after": new})

    before_services = {_service_key(item): item for item in before.get("services", [])}
    after_services = {_service_key(item): item for item in after.get("services", [])}
    before_relations = {_relationship_key(item): item for item in before.get("relationships", [])}
    after_relations = {_relationship_key(item): item for item in after.get("relationships", [])}

    result = {
        "schema_version": "1.0.0",
        "before_run": before.get("run", {}).get("id", ""),
        "after_run": after.get("run", {}).get("id", ""),
        "assets": {
            "added": [_asset_view(after_assets[key]) for key in added_keys],
            "removed": [_asset_view(before_assets[key]) for key in removed_keys],
            "changed": changed,
        },
        "services": {
            "added": [after_services[key] for key in sorted(after_services.keys() - before_services.keys())],
            "removed": [before_services[key] for key in sorted(before_services.keys() - after_services.keys())],
        },
        "relationships": {
            "added": [after_relations[key] for key in sorted(after_relations.keys() - before_relations.keys())],
            "removed": [before_relations[key] for key in sorted(before_relations.keys() - after_relations.keys())],
        },
    }
    result["summary"] = {
        "assets_added": len(result["assets"]["added"]),
        "assets_removed": len(result["assets"]["removed"]),
        "assets_changed": len(result["assets"]["changed"]),
        "services_added": len(result["services"]["added"]),
        "services_removed": len(result["services"]["removed"]),
        "relationships_added": len(result["relationships"]["added"]),
        "relationships_removed": len(result["relationships"]["removed"]),
    }
    return result


def _asset_key(asset: dict[str, Any]) -> str:
    asset_id = str(asset.get("id", ""))
    if asset_id:
        return "id:" + asset_id
    macs = sorted(str(value).lower() for value in asset.get("macs", []) if value)
    if macs:
        return "mac:" + "|".join(macs)
    addresses = sorted(str(value) for value in asset.get("addresses", []) if value)
    if addresses:
        return "address:" + "|".join(addresses)
    return "id:" + str(asset.get("id", ""))


def _asset_view(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": asset.get("id", ""),
        "kind": asset.get("kind", ""),
        "names": sorted(asset.get("names", [])),
        "addresses": sorted(asset.get("addresses", [])),
        "macs": sorted(value.lower() for value in asset.get("macs", [])),
        "roles": sorted(asset.get("roles", [])),
    }


def _service_key(service: dict[str, Any]) -> str:
    return "|".join(
        str(service.get(field, ""))
        for field in ("address", "port", "transport", "state")
    )


def _relationship_key(relationship: dict[str, Any]) -> str:
    return "|".join(
        str(relationship.get(field, ""))
        for field in ("type", "state", "from", "to", "local_port", "remote_port", "vlan")
    )
