package snmpv3

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"

	"github.com/Roger08G/netra/engine/internal/model"
	"github.com/Roger08G/netra/engine/internal/policy"
)

const (
	maxTargets   = 64
	maxRows      = 65536
	maxTextRunes = 1024

	oidSysDescr              = ".1.3.6.1.2.1.1.1.0"
	oidSysName               = ".1.3.6.1.2.1.1.5.0"
	oidIfDescr               = ".1.3.6.1.2.1.2.2.1.2"
	oidIfName                = ".1.3.6.1.2.1.31.1.1.1.1"
	oidBasePortIfIndex       = ".1.3.6.1.2.1.17.1.4.1.2"
	oidBridgeFDBPort         = ".1.3.6.1.2.1.17.4.3.1.2"
	oidQBridgeFDBPort        = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidQVlanFDBID            = ".1.3.6.1.2.1.17.7.1.4.2.1.3"
	oidLLDPLocalChassisType  = ".1.0.8802.1.1.2.1.3.1.0"
	oidLLDPLocalChassis      = ".1.0.8802.1.1.2.1.3.2.0"
	oidLLDPLocalPortID       = ".1.0.8802.1.1.2.1.3.7.1.3"
	oidLLDPRemoteChassisType = ".1.0.8802.1.1.2.1.4.1.1.4"
	oidLLDPRemoteChassisID   = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLLDPRemotePortID      = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLLDPRemoteSysName     = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidLLDPRemoteCaps        = ".1.0.8802.1.1.2.1.4.1.1.12"
)

var errTableLimit = errors.New("la tabla SNMP supera el límite de seguridad")

type Config struct {
	SchemaVersion string   `json:"schema_version"`
	Targets       []Target `json:"targets"`
}

type Target struct {
	Address           string `json:"address"`
	Port              int    `json:"port"`
	TimeoutMS         int    `json:"timeout_ms"`
	Retries           int    `json:"retries"`
	Username          string `json:"username"`
	AuthProtocol      string `json:"auth_protocol"`
	AuthPassphrase    string `json:"auth_passphrase"`
	PrivacyProtocol   string `json:"privacy_protocol"`
	PrivacyPassphrase string `json:"privacy_passphrase"`
	ContextName       string `json:"context_name,omitempty"`
}

type tables struct {
	ifName          []gosnmp.SnmpPDU
	ifDescr         []gosnmp.SnmpPDU
	basePortIfIndex []gosnmp.SnmpPDU
	bridgeFDB       []gosnmp.SnmpPDU
	qBridgeFDB      []gosnmp.SnmpPDU
	vlanFDBID       []gosnmp.SnmpPDU
	lldpLocalPort   []gosnmp.SnmpPDU
	lldpChassisType []gosnmp.SnmpPDU
	lldpChassis     []gosnmp.SnmpPDU
	lldpPort        []gosnmp.SnmpPDU
	lldpName        []gosnmp.SnmpPDU
	lldpCaps        []gosnmp.SnmpPDU
}

type tableRequest struct {
	stage       string
	oid         string
	destination *[]gosnmp.SnmpPDU
}

func Collect(ctx context.Context, config Config, plan model.Plan) ([]model.ManagedSwitch, []model.CoverageIssue, error) {
	if err := Validate(config, plan); err != nil {
		return nil, nil, err
	}
	switches := make([]model.ManagedSwitch, 0, len(config.Targets))
	issues := make([]model.CoverageIssue, 0)
	for _, target := range config.Targets {
		sw, targetIssues, err := collectTarget(ctx, target)
		issues = append(issues, targetIssues...)
		if err != nil {
			issues = append(issues, model.CoverageIssue{Source: "snmpv3", Target: target.Address, Stage: "session", Error: err.Error()})
			continue
		}
		switches = append(switches, sw)
	}
	resolveLLDPIdentities(switches)
	sort.Slice(switches, func(i, j int) bool { return switches[i].ID < switches[j].ID })
	return switches, issues, nil
}

func Validate(config Config, plan model.Plan) error {
	if config.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("versión de configuración SNMP no compatible: %q", config.SchemaVersion)
	}
	if plan.Passive {
		return errors.New("SNMPv3 no se puede usar con un plan pasivo")
	}
	if len(config.Targets) == 0 {
		return errors.New("la configuración SNMP no contiene destinos")
	}
	if len(config.Targets) > maxTargets {
		return fmt.Errorf("la configuración SNMP supera el máximo de %d destinos", maxTargets)
	}
	seen := map[string]bool{}
	for index, target := range config.Targets {
		address, err := netip.ParseAddr(strings.TrimSpace(target.Address))
		if err != nil || !address.Is4() {
			return fmt.Errorf("destino SNMP %d: address debe ser una IPv4 literal", index+1)
		}
		if !policy.Contains(plan, address) {
			return fmt.Errorf("destino SNMP %s fuera del alcance aprobado", address)
		}
		port := target.Port
		if port == 0 {
			port = 161
		}
		key := net.JoinHostPort(address.String(), strconv.Itoa(port))
		if seen[key] {
			return fmt.Errorf("destino SNMP duplicado: %s", key)
		}
		seen[key] = true
		if port < 1 || port > 65535 {
			return fmt.Errorf("destino SNMP %s: puerto fuera de rango", address)
		}
		if target.TimeoutMS < 250 || target.TimeoutMS > 10000 {
			return fmt.Errorf("destino SNMP %s: timeout_ms debe estar entre 250 y 10000", address)
		}
		if target.Retries < 0 || target.Retries > 3 {
			return fmt.Errorf("destino SNMP %s: retries debe estar entre 0 y 3", address)
		}
		if strings.TrimSpace(target.Username) == "" {
			return fmt.Errorf("destino SNMP %s: falta username", address)
		}
		if _, err := authProtocol(target.AuthProtocol); err != nil {
			return fmt.Errorf("destino SNMP %s: %w", address, err)
		}
		if _, err := privacyProtocol(target.PrivacyProtocol); err != nil {
			return fmt.Errorf("destino SNMP %s: %w", address, err)
		}
		if len(target.AuthPassphrase) < 8 || len(target.PrivacyPassphrase) < 8 {
			return fmt.Errorf("destino SNMP %s: las frases USM deben tener al menos 8 caracteres", address)
		}
	}
	return nil
}

func collectTarget(ctx context.Context, target Target) (model.ManagedSwitch, []model.CoverageIssue, error) {
	auth, _ := authProtocol(target.AuthProtocol)
	privacy, _ := privacyProtocol(target.PrivacyProtocol)
	port := target.Port
	if port == 0 {
		port = 161
	}
	client := &gosnmp.GoSNMP{
		Target:         target.Address,
		Port:           uint16(port),
		Transport:      "udp",
		Version:        gosnmp.Version3,
		Timeout:        time.Duration(target.TimeoutMS) * time.Millisecond,
		Retries:        target.Retries,
		MaxRepetitions: 25,
		Context:        ctx,
		ContextName:    target.ContextName,
		MsgFlags:       gosnmp.AuthPriv,
		SecurityModel:  gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 target.Username,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: target.AuthPassphrase,
			PrivacyProtocol:          privacy,
			PrivacyPassphrase:        target.PrivacyPassphrase,
		},
		Logger: gosnmp.NewLogger(log.New(io.Discard, "", 0)),
	}
	if err := client.Connect(); err != nil {
		return model.ManagedSwitch{}, nil, fmt.Errorf("no se pudo abrir la sesión SNMPv3: %w", err)
	}
	defer client.Close()

	scalars, err := client.Get([]string{oidSysName, oidSysDescr, oidLLDPLocalChassisType, oidLLDPLocalChassis})
	if err != nil {
		return model.ManagedSwitch{}, nil, fmt.Errorf("consulta de identidad SNMPv3: %w", err)
	}
	if scalars.Error != gosnmp.NoError {
		return model.ManagedSwitch{}, nil, fmt.Errorf("consulta de identidad SNMPv3: %s en índice %d", scalars.Error, scalars.ErrorIndex)
	}

	var raw tables
	requests := []tableRequest{
		{stage: "ifName", oid: oidIfName, destination: &raw.ifName},
		{stage: "ifDescr", oid: oidIfDescr, destination: &raw.ifDescr},
		{stage: "dot1dBasePortIfIndex", oid: oidBasePortIfIndex, destination: &raw.basePortIfIndex},
		{stage: "dot1dTpFdbPort", oid: oidBridgeFDBPort, destination: &raw.bridgeFDB},
		{stage: "dot1qTpFdbPort", oid: oidQBridgeFDBPort, destination: &raw.qBridgeFDB},
		{stage: "dot1qVlanFdbId", oid: oidQVlanFDBID, destination: &raw.vlanFDBID},
		{stage: "lldpLocPortId", oid: oidLLDPLocalPortID, destination: &raw.lldpLocalPort},
		{stage: "lldpRemChassisIdSubtype", oid: oidLLDPRemoteChassisType, destination: &raw.lldpChassisType},
		{stage: "lldpRemChassisId", oid: oidLLDPRemoteChassisID, destination: &raw.lldpChassis},
		{stage: "lldpRemPortId", oid: oidLLDPRemotePortID, destination: &raw.lldpPort},
		{stage: "lldpRemSysName", oid: oidLLDPRemoteSysName, destination: &raw.lldpName},
		{stage: "lldpRemSysCapEnabled", oid: oidLLDPRemoteCaps, destination: &raw.lldpCaps},
	}
	issues := make([]model.CoverageIssue, 0)
	for _, request := range requests {
		values, err := walkLimited(client, request.oid)
		if err != nil {
			issues = append(issues, model.CoverageIssue{Source: "snmpv3", Target: target.Address, Stage: request.stage, Error: err.Error()})
			continue
		}
		*request.destination = values
	}
	sw := parseSwitch(target.Address, scalars.Variables, raw, time.Now().UTC())
	return sw, issues, nil
}

func walkLimited(client *gosnmp.GoSNMP, root string) ([]gosnmp.SnmpPDU, error) {
	values := make([]gosnmp.SnmpPDU, 0)
	err := client.BulkWalk(root, func(pdu gosnmp.SnmpPDU) error {
		if len(values) >= maxRows {
			return errTableLimit
		}
		values = append(values, pdu)
		return nil
	})
	return values, err
}

func parseSwitch(address string, scalars []gosnmp.SnmpPDU, raw tables, observedAt time.Time) model.ManagedSwitch {
	name := scalarText(scalars, oidSysName)
	if name == "" {
		name = address
	}
	macs := make([]string, 0, 1)
	localChassisType, _ := integerValue(scalarValue(scalars, oidLLDPLocalChassisType))
	if mac := typedChassisMAC(localChassisType, scalarValue(scalars, oidLLDPLocalChassis)); mac != "" {
		macs = append(macs, mac)
	}
	portNames := indexedText(raw.ifDescr, oidIfDescr)
	for index, value := range indexedText(raw.ifName, oidIfName) {
		if value != "" {
			portNames[index] = value
		}
	}
	bridgeToIf := indexedIntegers(raw.basePortIfIndex, oidBasePortIfIndex)
	vlanByFDB := vlanMap(raw.vlanFDBID)
	fdb := parseFDB(raw.bridgeFDB, raw.qBridgeFDB, bridgeToIf, portNames, vlanByFDB)
	lldp := parseLLDP(raw, portNames, address)
	return model.ManagedSwitch{
		ID:                "snmp:" + address,
		Name:              name,
		Source:            "snmpv3",
		ObservedAt:        observedAt,
		ManagementAddress: address,
		MACs:              macs,
		Roles:             []string{"bridge"},
		FDB:               fdb,
		LLDP:              lldp,
	}
}

func parseFDB(classic, qbridge []gosnmp.SnmpPDU, bridgeToIf map[int]int, portNames map[int]string, vlanByFDB map[int][]int) []model.FDBEntry {
	entries := make([]model.FDBEntry, 0, len(classic)+len(qbridge))
	seen := map[string]bool{}
	add := func(mac string, bridgePort, vlan int) {
		if mac == "" || bridgePort <= 0 {
			return
		}
		port := portLabel(bridgePort, bridgeToIf, portNames)
		key := fmt.Sprintf("%s|%s|%d", mac, port, vlan)
		if !seen[key] {
			seen[key] = true
			entries = append(entries, model.FDBEntry{MAC: mac, Port: port, VLAN: vlan})
		}
	}
	for _, pdu := range classic {
		bridgePort, ok := integerValue(pdu.Value)
		if !ok {
			continue
		}
		parts := oidIndex(pdu.Name, oidBridgeFDBPort)
		add(macFromIndex(parts), bridgePort, 0)
	}
	for _, pdu := range qbridge {
		bridgePort, ok := integerValue(pdu.Value)
		if !ok {
			continue
		}
		parts := oidIndex(pdu.Name, oidQBridgeFDBPort)
		if len(parts) < 7 {
			continue
		}
		fdbID := parts[len(parts)-7]
		vlan := 0
		if candidates := vlanByFDB[fdbID]; len(candidates) == 1 {
			vlan = candidates[0]
		}
		add(macFromIndex(parts), bridgePort, vlan)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Port == entries[j].Port {
			if entries[i].VLAN == entries[j].VLAN {
				return entries[i].MAC < entries[j].MAC
			}
			return entries[i].VLAN < entries[j].VLAN
		}
		return entries[i].Port < entries[j].Port
	})
	return entries
}

func parseLLDP(raw tables, portNames map[int]string, observer string) []model.LLDPNeighbor {
	localPorts := indexedText(raw.lldpLocalPort, oidLLDPLocalPortID)
	type record struct {
		name           string
		port           string
		chassis        any
		chassisSubtype int
		caps           any
	}
	records := map[string]*record{}
	fillText := func(values []gosnmp.SnmpPDU, root string, setter func(*record, string)) {
		for _, pdu := range values {
			key := indexKey(oidIndex(pdu.Name, root))
			if key == "" {
				continue
			}
			if records[key] == nil {
				records[key] = &record{}
			}
			setter(records[key], pduText(pdu))
		}
	}
	fillText(raw.lldpName, oidLLDPRemoteSysName, func(item *record, value string) { item.name = value })
	fillText(raw.lldpPort, oidLLDPRemotePortID, func(item *record, value string) { item.port = value })
	for _, pdu := range raw.lldpChassis {
		key := indexKey(oidIndex(pdu.Name, oidLLDPRemoteChassisID))
		if key != "" {
			if records[key] == nil {
				records[key] = &record{}
			}
			records[key].chassis = pdu.Value
		}
	}
	for _, pdu := range raw.lldpChassisType {
		key := indexKey(oidIndex(pdu.Name, oidLLDPRemoteChassisType))
		if key != "" {
			if records[key] == nil {
				records[key] = &record{}
			}
			records[key].chassisSubtype, _ = integerValue(pdu.Value)
		}
	}
	for _, pdu := range raw.lldpCaps {
		key := indexKey(oidIndex(pdu.Name, oidLLDPRemoteCaps))
		if key != "" {
			if records[key] == nil {
				records[key] = &record{}
			}
			records[key].caps = pdu.Value
		}
	}
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	neighbors := make([]model.LLDPNeighbor, 0, len(keys))
	for _, key := range keys {
		parts := parseIndexKey(key)
		if len(parts) < 3 {
			continue
		}
		localNumber := parts[len(parts)-2]
		localPort := localPorts[localNumber]
		if localPort == "" {
			localPort = portNames[localNumber]
		}
		if localPort == "" {
			localPort = fmt.Sprintf("lldp-port:%d", localNumber)
		}
		item := records[key]
		remoteMAC := typedChassisMAC(item.chassisSubtype, item.chassis)
		remoteMACs := compact(remoteMAC)
		neighbors = append(neighbors, model.LLDPNeighbor{
			LocalPort:          localPort,
			RemoteDeviceID:     remoteID(observer, key, item.name, item.chassisSubtype, item.chassis),
			RemoteName:         item.name,
			RemotePort:         item.port,
			RemoteMACs:         remoteMACs,
			RemoteCapabilities: capabilities(item.caps),
		})
	}
	return neighbors
}

func resolveLLDPIdentities(switches []model.ManagedSwitch) {
	nameOwners := map[string]string{}
	nameCount := map[string]int{}
	macOwners := map[string]string{}
	for _, sw := range switches {
		name := strings.ToLower(strings.TrimSpace(sw.Name))
		if name != "" {
			nameCount[name]++
			nameOwners[name] = sw.ID
		}
		for _, mac := range sw.MACs {
			macOwners[mac] = sw.ID
		}
	}
	for switchIndex := range switches {
		for neighborIndex := range switches[switchIndex].LLDP {
			neighbor := &switches[switchIndex].LLDP[neighborIndex]
			for _, mac := range neighbor.RemoteMACs {
				if owner := macOwners[mac]; owner != "" {
					neighbor.RemoteDeviceID = owner
					break
				}
			}
			name := strings.ToLower(strings.TrimSpace(neighbor.RemoteName))
			if name != "" && nameCount[name] == 1 {
				neighbor.RemoteDeviceID = nameOwners[name]
			}
		}
	}
}

func indexedText(values []gosnmp.SnmpPDU, root string) map[int]string {
	result := map[int]string{}
	for _, pdu := range values {
		parts := oidIndex(pdu.Name, root)
		if len(parts) > 0 {
			result[parts[len(parts)-1]] = pduText(pdu)
		}
	}
	return result
}

func indexedIntegers(values []gosnmp.SnmpPDU, root string) map[int]int {
	result := map[int]int{}
	for _, pdu := range values {
		parts := oidIndex(pdu.Name, root)
		value, ok := integerValue(pdu.Value)
		if len(parts) > 0 && ok {
			result[parts[len(parts)-1]] = value
		}
	}
	return result
}

func vlanMap(values []gosnmp.SnmpPDU) map[int][]int {
	result := map[int][]int{}
	for _, pdu := range values {
		parts := oidIndex(pdu.Name, oidQVlanFDBID)
		fdbID, ok := integerValue(pdu.Value)
		if len(parts) < 1 || !ok {
			continue
		}
		vlan := parts[len(parts)-1]
		result[fdbID] = appendUniqueInt(result[fdbID], vlan)
	}
	return result
}

func portLabel(bridgePort int, bridgeToIf map[int]int, portNames map[int]string) string {
	ifIndex := bridgeToIf[bridgePort]
	if name := portNames[ifIndex]; name != "" {
		return name
	}
	if ifIndex > 0 {
		return fmt.Sprintf("ifIndex:%d", ifIndex)
	}
	return fmt.Sprintf("bridge-port:%d", bridgePort)
}

func macFromIndex(parts []int) string {
	if len(parts) < 6 {
		return ""
	}
	bytes := make([]byte, 6)
	for index, value := range parts[len(parts)-6:] {
		if value < 0 || value > 255 {
			return ""
		}
		bytes[index] = byte(value)
	}
	return net.HardwareAddr(bytes).String()
}

func oidIndex(name, root string) []int {
	name = strings.TrimPrefix(name, ".")
	root = strings.TrimPrefix(root, ".")
	if name == root {
		return nil
	}
	prefix := root + "."
	if !strings.HasPrefix(name, prefix) {
		return nil
	}
	segments := strings.Split(strings.TrimPrefix(name, prefix), ".")
	values := make([]int, 0, len(segments))
	for _, segment := range segments {
		value, err := strconv.Atoi(segment)
		if err != nil {
			return nil
		}
		values = append(values, value)
	}
	return values
}

func scalarText(values []gosnmp.SnmpPDU, oid string) string {
	return textValue(scalarValue(values, oid))
}

func scalarValue(values []gosnmp.SnmpPDU, oid string) any {
	wanted := strings.TrimPrefix(oid, ".")
	for _, pdu := range values {
		if strings.TrimPrefix(pdu.Name, ".") == wanted {
			return pdu.Value
		}
	}
	return nil
}

func pduText(pdu gosnmp.SnmpPDU) string {
	return textValue(pdu.Value)
}

func textValue(value any) string {
	var text string
	switch typed := value.(type) {
	case string:
		text = typed
	case []byte:
		text = string(typed)
	default:
		return ""
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	text = strings.Trim(strings.TrimSpace(text), "\x00")
	runes := []rune(text)
	if len(runes) > maxTextRunes {
		text = string(runes[:maxTextRunes])
	}
	return text
}

func integerValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case uint:
		return int(typed), true
	case uint32:
		return int(typed), true
	case uint64:
		if typed > uint64(^uint(0)>>1) {
			return 0, false
		}
		return int(typed), true
	case *big.Int:
		if typed.IsInt64() {
			return int(typed.Int64()), true
		}
	}
	return 0, false
}

func valueMAC(value any) string {
	bytes, ok := value.([]byte)
	if !ok || len(bytes) != 6 {
		return ""
	}
	mac := net.HardwareAddr(bytes).String()
	if mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return mac
}

func capabilities(value any) []string {
	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}
	names := []string{"other", "repeater", "bridge", "wlan_access_point", "router", "telephone", "docsis_cable_device", "station_only"}
	var result []string
	for bit, name := range names {
		byteIndex := bit / 8
		if byteIndex < len(bytes) && bytes[byteIndex]&(1<<uint(7-bit%8)) != 0 {
			result = append(result, name)
		}
	}
	return result
}

func remoteID(observer, key, name string, chassisSubtype int, chassis any) string {
	if mac := typedChassisMAC(chassisSubtype, chassis); mac != "" {
		return "lldp:" + strings.ReplaceAll(mac, ":", "")
	}
	material := observer + "|" + key + "|" + strings.ToLower(name) + "|" + textValue(chassis)
	if bytes, ok := chassis.([]byte); ok {
		material += "|" + fmt.Sprintf("%x", bytes)
	}
	sum := sha256.Sum256([]byte(material))
	return fmt.Sprintf("lldp:%x", sum[:8])
}

func typedChassisMAC(subtype int, value any) string {
	if subtype != 4 {
		return ""
	}
	return valueMAC(value)
}

func authProtocol(value string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return 0, fmt.Errorf("auth_protocol debe ser SHA, SHA224, SHA256, SHA384 o SHA512")
	}
}

func privacyProtocol(value string) (gosnmp.SnmpV3PrivProtocol, error) {
	if strings.EqualFold(strings.TrimSpace(value), "AES") {
		return gosnmp.AES, nil
	}
	return 0, fmt.Errorf("privacy_protocol debe ser AES")
}

func compact(value string) []string {
	if value == "" {
		return nil
	}
	return []string{value}
}

func appendUniqueInt(values []int, value int) []int {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}

func indexKey(values []int) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(value)
	}
	return strings.Join(parts, ".")
}

func parseIndexKey(key string) []int {
	segments := strings.Split(key, ".")
	values := make([]int, 0, len(segments))
	for _, segment := range segments {
		value, err := strconv.Atoi(segment)
		if err != nil {
			return nil
		}
		values = append(values, value)
	}
	return values
}
