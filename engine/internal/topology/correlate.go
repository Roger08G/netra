package topology

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Roger08G/netra/engine/internal/model"
)

func Correlate(assets []model.Asset, managed *model.ManagedEvidence) ([]model.Asset, []model.Relationship, error) {
	if managed == nil {
		return assets, nil, nil
	}
	if managed.SchemaVersion != model.SchemaVersion {
		return nil, nil, fmt.Errorf("versión de evidencia gestionada no compatible: %q", managed.SchemaVersion)
	}
	observedAt := managed.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	byID := make(map[string]*model.Asset)
	byMAC := make(map[string]*model.Asset)
	for index := range assets {
		byID[assets[index].ID] = &assets[index]
		for _, mac := range assets[index].MACs {
			byMAC[normalizeMAC(mac)] = &assets[index]
		}
	}
	for _, sw := range managed.Switches {
		if strings.TrimSpace(sw.ID) == "" {
			return nil, nil, fmt.Errorf("un switch gestionado no tiene id")
		}
		switchObservedAt := sw.ObservedAt
		if switchObservedAt.IsZero() {
			switchObservedAt = observedAt
		}
		asset := model.Asset{ID: sw.ID, Kind: "device", Names: compact(sw.Name), Roles: mergeStrings([]string{"switch"}, sw.Roles), MACs: normalizeMACs(sw.MACs)}
		if sw.ManagementAddress != "" {
			asset.Addresses = []string{sw.ManagementAddress}
		}
		asset.Evidence = []model.Evidence{{Source: evidenceSource(sw.Source, "managed_inventory"), ObservedAt: switchObservedAt, Observer: sw.ID}}
		assets = upsertAsset(assets, asset)
	}
	byID, byMAC = indexes(assets)

	var relationships []model.Relationship
	for _, sw := range managed.Switches {
		switchObservedAt := sw.ObservedAt
		if switchObservedAt.IsZero() {
			switchObservedAt = observedAt
		}
		lldpByPort := map[string]model.LLDPNeighbor{}
		for _, neighbor := range sw.LLDP {
			if neighbor.LocalPort == "" || neighbor.RemoteDeviceID == "" {
				continue
			}
			remote, exists := byID[neighbor.RemoteDeviceID]
			if !exists {
				asset := model.Asset{ID: neighbor.RemoteDeviceID, Kind: "device", Names: compact(neighbor.RemoteName), MACs: normalizeMACs(neighbor.RemoteMACs), Roles: append([]string(nil), neighbor.RemoteCapabilities...), Evidence: []model.Evidence{{Source: evidenceSource(sw.Source, "lldp"), ObservedAt: switchObservedAt, Observer: sw.ID}}}
				assets = append(assets, asset)
				byID, byMAC = indexes(assets)
				remote = byID[neighbor.RemoteDeviceID]
			}
			remote.Roles = mergeStrings(remote.Roles, neighbor.RemoteCapabilities)
			lldpByPort[neighbor.LocalPort] = neighbor
			evidence := model.Evidence{Source: evidenceSource(sw.Source, "lldp"), ObservedAt: switchObservedAt, Observer: sw.ID, Details: map[string]any{"local_port": neighbor.LocalPort, "remote_port": neighbor.RemotePort}}
			relationships = append(relationships,
				relation("lldp_neighbor", "observed", sw.ID, remote.ID, neighbor.LocalPort, neighbor.RemotePort, 0, evidence, "El vecino fue anunciado por LLDP; es una observación de adyacencia, no una inspección visual del cable."),
				relation("physical_link", "inferred", sw.ID, remote.ID, neighbor.LocalPort, neighbor.RemotePort, 0, evidence, "La conexión física se infiere de LLDP. Requiere evidencia bilateral o inspección para considerarse verificada."),
			)
		}

		fdbByPort := map[string][]model.FDBEntry{}
		for _, entry := range sw.FDB {
			mac := normalizeMAC(entry.MAC)
			if mac == "" || entry.Port == "" {
				continue
			}
			entry.MAC = mac
			fdbByPort[entry.Port] = append(fdbByPort[entry.Port], entry)
			asset, exists := byMAC[mac]
			if !exists {
				unknown := model.Asset{ID: "mac:" + strings.ReplaceAll(mac, ":", ""), Kind: "device", MACs: []string{mac}, Roles: []string{"unknown"}, Evidence: []model.Evidence{{Source: evidenceSource(sw.Source, "fdb"), ObservedAt: switchObservedAt, Observer: sw.ID}}}
				assets = append(assets, unknown)
				byID, byMAC = indexes(assets)
				asset = byMAC[mac]
			}
			evidence := model.Evidence{Source: evidenceSource(sw.Source, "fdb"), ObservedAt: switchObservedAt, Observer: sw.ID, Details: map[string]any{"port": entry.Port, "vlan": entry.VLAN, "mac": mac}}
			explanation := "El switch aprendió esta MAC a través del puerto. Esto no demuestra conexión física directa."
			if neighbor, ok := lldpByPort[entry.Port]; ok && isBridge(neighbor.RemoteCapabilities) {
				explanation += " LLDP anuncia un bridge en el mismo puerto, por lo que el activo puede estar detrás de ese equipo."
			}
			relationships = append(relationships, relation("mac_learned_on_port", "observed", sw.ID, asset.ID, entry.Port, "", entry.VLAN, evidence, explanation))
		}

		for port, entries := range fdbByPort {
			if len(uniqueMACs(entries)) != 1 {
				continue
			}
			if neighbor, ok := lldpByPort[port]; ok && isBridge(neighbor.RemoteCapabilities) {
				continue
			}
			entry := entries[0]
			asset := byMAC[normalizeMAC(entry.MAC)]
			if asset == nil || asset.ID == sw.ID {
				continue
			}
			evidence := model.Evidence{Source: evidenceSource(sw.Source, "fdb"), ObservedAt: switchObservedAt, Observer: sw.ID, Details: map[string]any{"port": port, "single_mac": true}}
			relationships = append(relationships, relation("physical_attachment", "inferred", sw.ID, asset.ID, port, "", entry.VLAN, evidence, "Se infiere un posible acceso directo porque solo se observó una MAC y no hay un bridge LLDP en el puerto; no está verificado."))
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	sort.Slice(relationships, func(i, j int) bool { return relationships[i].ID < relationships[j].ID })
	return assets, deduplicate(relationships), nil
}

func relation(kind, state, from, to, localPort, remotePort string, vlan int, evidence model.Evidence, explanation string) model.Relationship {
	key := strings.Join([]string{kind, from, to, localPort, remotePort, fmt.Sprint(vlan)}, "|")
	sum := sha256.Sum256([]byte(key))
	return model.Relationship{ID: fmt.Sprintf("rel:%x", sum[:8]), Type: kind, State: state, From: from, To: to, LocalPort: localPort, RemotePort: remotePort, VLAN: vlan, Evidence: []model.Evidence{evidence}, Explanation: explanation}
}

func indexes(assets []model.Asset) (map[string]*model.Asset, map[string]*model.Asset) {
	byID := make(map[string]*model.Asset, len(assets))
	byMAC := make(map[string]*model.Asset)
	for index := range assets {
		byID[assets[index].ID] = &assets[index]
		for _, mac := range assets[index].MACs {
			byMAC[normalizeMAC(mac)] = &assets[index]
		}
	}
	return byID, byMAC
}

func upsertAsset(assets []model.Asset, incoming model.Asset) []model.Asset {
	for index := range assets {
		if assets[index].ID == incoming.ID {
			assets[index].Names = mergeStrings(assets[index].Names, incoming.Names)
			assets[index].Addresses = mergeStrings(assets[index].Addresses, incoming.Addresses)
			assets[index].MACs = mergeStrings(assets[index].MACs, incoming.MACs)
			assets[index].Roles = mergeStrings(assets[index].Roles, incoming.Roles)
			assets[index].Evidence = append(assets[index].Evidence, incoming.Evidence...)
			return assets
		}
	}
	return append(assets, incoming)
}

func normalizeMAC(value string) string {
	parsed, err := net.ParseMAC(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", ":"))
	if err != nil || len(parsed) != 6 {
		return ""
	}
	return parsed.String()
}

func normalizeMACs(values []string) []string {
	var normalized []string
	for _, value := range values {
		if mac := normalizeMAC(value); mac != "" {
			normalized = mergeStrings(normalized, []string{mac})
		}
	}
	return normalized
}

func mergeStrings(left, right []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(left)+len(right))
	for _, values := range [][]string{left, right} {
		for _, value := range values {
			if value != "" && !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	return result
}

func compact(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return []string{value}
}

func isBridge(capabilities []string) bool {
	for _, capability := range capabilities {
		lower := strings.ToLower(capability)
		if lower == "bridge" || lower == "switch" {
			return true
		}
	}
	return false
}

func uniqueMACs(entries []model.FDBEntry) []string {
	seen := map[string]bool{}
	var values []string
	for _, entry := range entries {
		mac := normalizeMAC(entry.MAC)
		if mac != "" && !seen[mac] {
			seen[mac] = true
			values = append(values, mac)
		}
	}
	return values
}

func deduplicate(values []model.Relationship) []model.Relationship {
	seen := map[string]bool{}
	result := make([]model.Relationship, 0, len(values))
	for _, value := range values {
		if !seen[value.ID] {
			seen[value.ID] = true
			result = append(result, value)
		}
	}
	return result
}

func evidenceSource(source, kind string) string {
	if source == "" || source == "import" {
		return kind
	}
	return source + ":" + kind
}
