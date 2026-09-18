package runner

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Roger08G/netra/engine/internal/collector"
	"github.com/Roger08G/netra/engine/internal/collector/snmpv3"
	"github.com/Roger08G/netra/engine/internal/model"
	"github.com/Roger08G/netra/engine/internal/policy"
	"github.com/Roger08G/netra/engine/internal/topology"
)

type ScanInput struct {
	Plan            model.Plan             `json:"plan"`
	Services        bool                   `json:"services"`
	Concurrency     int                    `json:"concurrency"`
	TimeoutMS       int                    `json:"timeout_ms"`
	Output          string                 `json:"output"`
	ManagedEvidence *model.ManagedEvidence `json:"managed_evidence"`
	SNMP            *snmpv3.Config         `json:"snmp,omitempty"`
}

type Emit func(eventType string, payload any)

func Scan(ctx context.Context, input ScanInput, emit Emit) (model.Artifact, error) {
	targetCount, err := policy.ValidatePlan(input.Plan)
	if err != nil {
		return model.Artifact{}, fmt.Errorf("plan rechazado por el motor: %w", err)
	}
	if input.Output == "" {
		return model.Artifact{}, fmt.Errorf("falta la ruta de salida")
	}
	if input.Concurrency < 1 || input.Concurrency > 256 {
		return model.Artifact{}, fmt.Errorf("concurrency debe estar entre 1 y 256")
	}
	if input.TimeoutMS < 50 || input.TimeoutMS > 10000 {
		return model.Artifact{}, fmt.Errorf("timeout_ms debe estar entre 50 y 10000")
	}
	if input.SNMP != nil {
		if err := snmpv3.Validate(*input.SNMP, input.Plan); err != nil {
			return model.Artifact{}, fmt.Errorf("configuración SNMPv3: %w", err)
		}
	}

	startedAt := time.Now().UTC()
	runHash := sha256.Sum256([]byte(fmt.Sprintf("%d", startedAt.UnixNano())))
	runID := fmt.Sprintf("run-%s-%x", startedAt.Format("20060102T150405Z"), runHash[:3])
	emit("run.started", map[string]any{"run_id": runID, "scope": input.Plan.Scope, "passive": input.Plan.Passive})

	local := collector.LocalAsset(input.Plan, startedAt)
	assets := []model.Asset{local}
	issues := make([]model.CoverageIssue, 0)

	neighbors, neighborErr := collector.ReadNeighbors(input.Plan)
	if neighborErr != nil {
		issues = append(issues, model.CoverageIssue{Source: "neighbor_cache", Stage: "collect", Error: neighborErr.Error()})
		emit("collector.completed", map[string]any{"collector": "neighbor_cache", "status": "unavailable", "detail": neighborErr.Error()})
	} else {
		assets = mergeNeighbors(assets, neighbors, startedAt)
		emit("collector.completed", map[string]any{"collector": "neighbor_cache", "status": "ok", "observations": len(neighbors)})
	}

	attempted := 0
	responsive := 0
	timeout := time.Duration(input.TimeoutMS) * time.Millisecond
	if !input.Plan.Passive {
		results, err := collector.ProbeTargets(ctx, input.Plan, timeout, input.Concurrency)
		if err != nil {
			return model.Artifact{}, fmt.Errorf("descubrimiento activo: %w", err)
		}
		attempted = len(results)
		for _, result := range results {
			if !result.Reachable {
				continue
			}
			responsive++
			assets = upsertAddress(assets, result.Address, model.Evidence{Source: "icmp_echo", ObservedAt: time.Now().UTC(), Observer: local.ID, Details: map[string]any{"probe_duration_ms": result.ProbeDurationMS}})
			emit("observation.recorded", map[string]any{"source": "icmp_echo", "address": result.Address, "reachable": true})
		}
		emit("collector.completed", map[string]any{"collector": "icmp_echo", "status": "ok", "attempted": attempted, "responsive": responsive})
		if refreshed, err := collector.ReadNeighbors(input.Plan); err == nil {
			neighbors = mergeNeighborLists(neighbors, refreshed)
			assets = mergeNeighbors(assets, refreshed, time.Now().UTC())
		}
	}

	services := make([]model.Service, 0)
	if input.Services && !input.Plan.Passive {
		var addresses []string
		for _, asset := range assets {
			if asset.ID == local.ID {
				continue
			}
			addresses = append(addresses, asset.Addresses...)
		}
		services = collector.CheckServices(ctx, uniqueStrings(addresses), timeout, input.Concurrency)
		for index := range services {
			for _, asset := range assets {
				if contains(asset.Addresses, services[index].Address) {
					services[index].AssetID = asset.ID
					break
				}
			}
		}
		emit("collector.completed", map[string]any{"collector": "tcp_connect", "status": "ok", "open_services": len(services)})
	}

	managed := cloneManagedEvidence(input.ManagedEvidence)
	if input.SNMP != nil {
		switches, snmpIssues, err := snmpv3.Collect(ctx, *input.SNMP, input.Plan)
		if err != nil {
			return model.Artifact{}, fmt.Errorf("configuración SNMPv3: %w", err)
		}
		issues = append(issues, snmpIssues...)
		managed = mergeManagedEvidence(managed, switches)
		status := "ok"
		if len(snmpIssues) > 0 {
			status = "partial"
		}
		emit("collector.completed", map[string]any{"collector": "snmpv3", "status": status, "targets": len(input.SNMP.Targets), "switches": len(switches), "issues": len(snmpIssues)})
	}

	assets, relationships, err := topology.Correlate(assets, managed)
	if err != nil {
		return model.Artifact{}, fmt.Errorf("correlación de topología: %w", err)
	}
	if input.ManagedEvidence != nil {
		emit("collector.completed", map[string]any{"collector": "managed_evidence", "status": "ok", "switches": len(input.ManagedEvidence.Switches)})
	}
	if relationships == nil {
		relationships = make([]model.Relationship, 0)
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].Address == services[j].Address {
			return services[i].Port < services[j].Port
		}
		return services[i].Address < services[j].Address
	})
	sort.Slice(assets, func(i, j int) bool { return assets[i].ID < assets[j].ID })
	methods := []string{"local_interface", "neighbor_cache"}
	if !input.Plan.Passive {
		methods = append(methods, "icmp_echo")
	}
	if input.Services && !input.Plan.Passive {
		methods = append(methods, "tcp_connect")
	}
	managedCount := 0
	if managed != nil {
		managedCount = len(managed.Switches)
	}
	if input.ManagedEvidence != nil {
		methods = append(methods, "managed_evidence_import")
	}
	if input.SNMP != nil {
		methods = append(methods, "snmpv3_authpriv")
	}
	mode := "active"
	if input.Plan.Passive {
		mode = "passive"
	}
	artifact := model.Artifact{
		SchemaVersion:  model.SchemaVersion,
		ProductVersion: model.ProductVersion,
		Run:            model.Run{ID: runID, StartedAt: startedAt, CompletedAt: time.Now().UTC(), Mode: mode, Interface: input.Plan.Interface, Scope: input.Plan.Scope, Exclude: input.Plan.Exclude},
		Coverage:       model.Coverage{AttemptedIPv4: attempted, Responsive: responsive, NeighborCache: len(neighbors), ManagedSources: managedCount, Methods: methods, Issues: issues, Statement: coverageStatement(input.Plan, targetCount, managedCount, input.SNMP != nil)},
		Assets:         assets, Relationships: relationships, Services: services, Findings: []any{},
	}
	if err := writeArtifact(input.Output, artifact); err != nil {
		return model.Artifact{}, err
	}
	emit("run.completed", map[string]any{"run_id": runID, "artifact": input.Output, "summary": map[string]int{"assets": len(assets), "relationships": len(relationships), "services": len(services), "issues": len(issues)}})
	return artifact, nil
}

func mergeNeighbors(assets []model.Asset, neighbors []collector.Neighbor, observedAt time.Time) []model.Asset {
	for _, neighbor := range neighbors {
		evidence := model.Evidence{Source: "neighbor_cache", ObservedAt: observedAt, Details: map[string]any{"address": neighbor.Address, "mac": neighbor.MAC}}
		matched := -1
		for index := range assets {
			if contains(assets[index].Addresses, neighbor.Address) || contains(assets[index].MACs, neighbor.MAC) {
				matched = index
				break
			}
		}
		if matched >= 0 {
			assets[matched].Addresses = appendUnique(assets[matched].Addresses, neighbor.Address)
			assets[matched].MACs = appendUnique(assets[matched].MACs, neighbor.MAC)
			assets[matched].Evidence = append(assets[matched].Evidence, evidence)
			continue
		}
		assets = append(assets, model.Asset{ID: "mac:" + strings.ReplaceAll(neighbor.MAC, ":", ""), Kind: "device", Addresses: []string{neighbor.Address}, MACs: []string{neighbor.MAC}, Roles: []string{"unknown"}, Evidence: []model.Evidence{evidence}})
	}
	return assets
}

func upsertAddress(assets []model.Asset, address string, evidence model.Evidence) []model.Asset {
	for index := range assets {
		if contains(assets[index].Addresses, address) {
			assets[index].Evidence = append(assets[index].Evidence, evidence)
			return assets
		}
	}
	return append(assets, model.Asset{ID: "ip:" + strings.ReplaceAll(address, ".", "-"), Kind: "device", Addresses: []string{address}, Roles: []string{"unknown"}, Evidence: []model.Evidence{evidence}})
}

func writeArtifact(path string, artifact model.Artifact) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("crear directorio de salida: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".netra-*.tmp")
	if err != nil {
		return fmt.Errorf("crear artefacto temporal: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(artifact); err != nil {
		temporary.Close()
		return fmt.Errorf("serializar artefacto: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sincronizar artefacto: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("reemplazar artefacto existente: %w", err)
		}
		if err := os.Rename(temporaryName, path); err != nil {
			return fmt.Errorf("publicar artefacto: %w", err)
		}
	}
	return nil
}

func coverageStatement(plan model.Plan, targets, managed int, snmpAttempted bool) string {
	if plan.Passive {
		return "Se registraron únicamente fuentes locales y evidencia importada; la ausencia de un activo no demuestra que esté desconectado."
	}
	statement := fmt.Sprintf("Se intentó descubrimiento de bajo impacto sobre %d direcciones IPv4 autorizadas. El resultado no equivale a una red analizada al 100 %%.", targets)
	if managed == 0 && snmpAttempted {
		statement += " Se intentó consultar infraestructura gestionada, pero no se obtuvo una fuente utilizable; revisa coverage.issues."
	} else if managed == 0 {
		statement += " No se consultó infraestructura gestionada; los puertos físicos permanecen sin verificar."
	}
	return statement
}

func cloneManagedEvidence(source *model.ManagedEvidence) *model.ManagedEvidence {
	if source == nil {
		return nil
	}
	clone := *source
	clone.Switches = append([]model.ManagedSwitch{}, source.Switches...)
	return &clone
}

func mergeManagedEvidence(current *model.ManagedEvidence, switches []model.ManagedSwitch) *model.ManagedEvidence {
	if current == nil {
		current = &model.ManagedEvidence{SchemaVersion: model.SchemaVersion, ObservedAt: time.Now().UTC(), Switches: make([]model.ManagedSwitch, 0, len(switches))}
	}
	for _, incoming := range switches {
		merged := false
		for index := range current.Switches {
			if current.Switches[index].ID != incoming.ID {
				continue
			}
			existing := &current.Switches[index]
			if incoming.Name != "" {
				existing.Name = incoming.Name
			}
			if incoming.Source != "" {
				existing.Source = incoming.Source
			}
			if !incoming.ObservedAt.IsZero() {
				existing.ObservedAt = incoming.ObservedAt
			}
			if incoming.ManagementAddress != "" {
				existing.ManagementAddress = incoming.ManagementAddress
			}
			existing.MACs = mergeStrings(existing.MACs, incoming.MACs)
			existing.Roles = mergeStrings(existing.Roles, incoming.Roles)
			existing.LLDP = append(existing.LLDP, incoming.LLDP...)
			existing.FDB = append(existing.FDB, incoming.FDB...)
			merged = true
			break
		}
		if !merged {
			current.Switches = append(current.Switches, incoming)
		}
	}
	return current
}

func mergeNeighborLists(left, right []collector.Neighbor) []collector.Neighbor {
	seen := map[string]bool{}
	var merged []collector.Neighbor
	for _, list := range [][]collector.Neighbor{left, right} {
		for _, item := range list {
			key := item.Address + "|" + item.MAC
			if !seen[key] {
				seen[key] = true
				merged = append(merged, item)
			}
		}
	}
	return merged
}

func appendUnique(values []string, value string) []string {
	if value != "" && !contains(values, value) {
		return append(values, value)
	}
	return values
}

func uniqueStrings(values []string) []string {
	var unique []string
	for _, value := range values {
		unique = appendUnique(unique, value)
	}
	return unique
}

func mergeStrings(left, right []string) []string {
	result := append([]string{}, left...)
	for _, value := range right {
		result = appendUnique(result, value)
	}
	return result
}

func contains(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}
