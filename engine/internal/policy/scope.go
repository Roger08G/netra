package policy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/Roger08G/netra/engine/internal/model"
)

const MaxActiveTargets = 4096

type PlanInput struct {
	Scope     []string `json:"scope"`
	Interface string   `json:"interface"`
	Exclude   []string `json:"exclude"`
	Passive   bool     `json:"passive"`
}

func CreatePlan(input PlanInput) (model.Plan, error) {
	scope := append([]string{}, input.Scope...)
	iface := strings.TrimSpace(input.Interface)
	if len(scope) == 0 {
		detectedInterface, detectedScope, err := DetectDefaultScope(iface)
		if err != nil {
			return model.Plan{}, err
		}
		iface, scope = detectedInterface, []string{detectedScope}
	}
	plan := model.Plan{
		SchemaVersion: model.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
		Interface:     iface,
		Scope:         scope,
		Exclude:       append([]string{}, input.Exclude...),
		Passive:       input.Passive,
	}
	count, err := ValidatePlan(plan)
	if err != nil {
		return model.Plan{}, err
	}
	plan.TargetCount = count
	return plan, nil
}

func ValidatePlan(plan model.Plan) (int, error) {
	if plan.SchemaVersion != model.SchemaVersion {
		return 0, fmt.Errorf("versión de plan no compatible: %q", plan.SchemaVersion)
	}
	if len(plan.Scope) == 0 {
		return 0, errors.New("el plan no contiene ningún alcance")
	}
	prefixes := make([]netip.Prefix, 0, len(plan.Scope))
	count := 0
	for _, raw := range plan.Scope {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil || !prefix.Addr().Is4() {
			return 0, fmt.Errorf("alcance IPv4 no válido: %q", raw)
		}
		prefix = prefix.Masked()
		if !allowedNetwork(prefix.Addr()) {
			return 0, fmt.Errorf("el alcance %s no es privado ni link-local", prefix)
		}
		prefixes = append(prefixes, prefix)
		count += usableAddressCount(prefix)
	}
	for _, raw := range plan.Exclude {
		if err := validateExclusion(raw, prefixes); err != nil {
			return 0, err
		}
	}
	if !plan.Passive && count > MaxActiveTargets {
		return 0, fmt.Errorf("el alcance activo contiene %d objetivos; el máximo es %d", count, MaxActiveTargets)
	}
	return count, nil
}

func DetectDefaultScope(requested string) (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("no se pudieron enumerar interfaces: %w", err)
	}
	for _, iface := range interfaces {
		if requested != "" && !strings.EqualFold(iface.Name, requested) {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || isVirtualName(iface.Name) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip, network, err := net.ParseCIDR(address.String())
			if err != nil || ip.To4() == nil || !allowedIP(ip) {
				continue
			}
			ones, _ := network.Mask.Size()
			masked := ip.Mask(network.Mask)
			return iface.Name, fmt.Sprintf("%s/%d", masked.String(), ones), nil
		}
	}
	if requested != "" {
		return "", "", fmt.Errorf("la interfaz %q no existe, está inactiva o no tiene IPv4 privada", requested)
	}
	return "", "", errors.New("no se encontró una interfaz activa con IPv4 privada; usa --interface y --scope")
}

func Contains(plan model.Plan, address netip.Addr) bool {
	inside := false
	for _, raw := range plan.Scope {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(address) {
			inside = true
			break
		}
	}
	if !inside {
		return false
	}
	for _, raw := range plan.Exclude {
		if prefix, err := parseIPOrPrefix(raw); err == nil && prefix.Contains(address) {
			return false
		}
	}
	return true
}

func Targets(plan model.Plan) ([]netip.Addr, error) {
	if _, err := ValidatePlan(plan); err != nil {
		return nil, err
	}
	var targets []netip.Addr
	for _, raw := range plan.Scope {
		prefix, _ := netip.ParsePrefix(raw)
		prefix = prefix.Masked()
		for address := prefix.Addr(); prefix.Contains(address); address = address.Next() {
			if isNetworkOrBroadcast(address, prefix) || !Contains(plan, address) {
				continue
			}
			targets = append(targets, address)
		}
	}
	return targets, nil
}

func validateExclusion(raw string, scopes []netip.Prefix) error {
	prefix, err := parseIPOrPrefix(raw)
	if err != nil {
		return fmt.Errorf("exclusión no válida %q: %w", raw, err)
	}
	for _, scope := range scopes {
		if scope.Contains(prefix.Addr()) {
			return nil
		}
	}
	return fmt.Errorf("la exclusión %s no pertenece a ningún alcance", raw)
}

func parseIPOrPrefix(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if address, err := netip.ParseAddr(raw); err == nil {
		if !address.Is4() {
			return netip.Prefix{}, errors.New("solo se admite IPv4 en esta entrega")
		}
		return netip.PrefixFrom(address, 32), nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() {
		return netip.Prefix{}, errors.New("se esperaba una IPv4 o un CIDR IPv4")
	}
	return prefix.Masked(), nil
}

func usableAddressCount(prefix netip.Prefix) int {
	bits := prefix.Bits()
	if bits >= 31 {
		return 1 << (32 - bits)
	}
	return (1 << (32 - bits)) - 2
}

func allowedNetwork(address netip.Addr) bool {
	return address.IsPrivate() || address.IsLinkLocalUnicast()
}

func allowedIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip.To4())
	return ok && allowedNetwork(address)
}

func isVirtualName(name string) bool {
	lower := strings.ToLower(name)
	for _, marker := range []string{"loopback", "vethernet", "vmware", "virtualbox", "wsl", "docker"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isNetworkOrBroadcast(address netip.Addr, prefix netip.Prefix) bool {
	if prefix.Bits() >= 31 {
		return false
	}
	value := binary.BigEndian.Uint32(address.AsSlice())
	base := binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())
	hostBits := 32 - prefix.Bits()
	broadcast := base | uint32((uint64(1)<<hostBits)-1)
	return value == base || value == broadcast
}
