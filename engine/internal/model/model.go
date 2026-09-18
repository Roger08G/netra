package model

import "time"

const SchemaVersion = "1.0.0"
const ProductVersion = "1.0.0"

type Evidence struct {
	Source     string         `json:"source"`
	ObservedAt time.Time      `json:"observed_at"`
	Observer   string         `json:"observer,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

type Asset struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Names     []string   `json:"names,omitempty"`
	Addresses []string   `json:"addresses,omitempty"`
	MACs      []string   `json:"macs,omitempty"`
	Roles     []string   `json:"roles,omitempty"`
	Evidence  []Evidence `json:"evidence,omitempty"`
}

type Relationship struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	State       string     `json:"state"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	LocalPort   string     `json:"local_port,omitempty"`
	RemotePort  string     `json:"remote_port,omitempty"`
	VLAN        int        `json:"vlan,omitempty"`
	Evidence    []Evidence `json:"evidence"`
	Explanation string     `json:"explanation"`
}

type Service struct {
	AssetID    string    `json:"asset_id"`
	Address    string    `json:"address"`
	Port       int       `json:"port"`
	Transport  string    `json:"transport"`
	State      string    `json:"state"`
	ObservedAt time.Time `json:"observed_at"`
}

type Plan struct {
	SchemaVersion string    `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	Interface     string    `json:"interface,omitempty"`
	Scope         []string  `json:"scope"`
	Exclude       []string  `json:"exclude"`
	Passive       bool      `json:"passive"`
	TargetCount   int       `json:"target_count"`
}

type Run struct {
	ID          string    `json:"id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Mode        string    `json:"mode"`
	Interface   string    `json:"interface,omitempty"`
	Scope       []string  `json:"scope"`
	Exclude     []string  `json:"exclude"`
}

type Coverage struct {
	AttemptedIPv4  int             `json:"attempted_ipv4"`
	Responsive     int             `json:"responsive"`
	NeighborCache  int             `json:"neighbor_cache"`
	ManagedSources int             `json:"managed_sources"`
	Methods        []string        `json:"methods"`
	Issues         []CoverageIssue `json:"issues"`
	Statement      string          `json:"statement"`
}

type CoverageIssue struct {
	Source string `json:"source"`
	Target string `json:"target,omitempty"`
	Stage  string `json:"stage"`
	Error  string `json:"error"`
}

type Artifact struct {
	SchemaVersion  string         `json:"schema_version"`
	ProductVersion string         `json:"product_version"`
	Run            Run            `json:"run"`
	Coverage       Coverage       `json:"coverage"`
	Assets         []Asset        `json:"assets"`
	Relationships  []Relationship `json:"relationships"`
	Services       []Service      `json:"services"`
	Findings       []any          `json:"findings"`
}

type ManagedEvidence struct {
	SchemaVersion string          `json:"schema_version"`
	ObservedAt    time.Time       `json:"observed_at"`
	Switches      []ManagedSwitch `json:"switches"`
}

type ManagedSwitch struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Source            string         `json:"source,omitempty"`
	ObservedAt        time.Time      `json:"observed_at,omitempty"`
	ManagementAddress string         `json:"management_address,omitempty"`
	MACs              []string       `json:"macs,omitempty"`
	Roles             []string       `json:"roles,omitempty"`
	LLDP              []LLDPNeighbor `json:"lldp_neighbors,omitempty"`
	FDB               []FDBEntry     `json:"fdb,omitempty"`
}

type LLDPNeighbor struct {
	LocalPort          string   `json:"local_port"`
	RemoteDeviceID     string   `json:"remote_device_id"`
	RemoteName         string   `json:"remote_name,omitempty"`
	RemotePort         string   `json:"remote_port,omitempty"`
	RemoteMACs         []string `json:"remote_macs,omitempty"`
	RemoteCapabilities []string `json:"remote_capabilities,omitempty"`
}

type FDBEntry struct {
	MAC  string `json:"mac"`
	Port string `json:"port"`
	VLAN int    `json:"vlan,omitempty"`
}
