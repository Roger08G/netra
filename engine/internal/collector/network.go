package collector

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Roger08G/netra/engine/internal/model"
	"github.com/Roger08G/netra/engine/internal/policy"
)

type Neighbor struct {
	Address string
	MAC     string
}

type Reachability struct {
	Address         string
	Reachable       bool
	ProbeDurationMS float64
}

func LocalAsset(plan model.Plan, observedAt time.Time) model.Asset {
	hostname, _ := os.Hostname()
	asset := model.Asset{ID: "local:" + safeID(hostname), Kind: "device", Names: []string{hostname}, Roles: []string{"observation_point"}}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if plan.Interface != "" && !strings.EqualFold(plan.Interface, iface.Name) {
			continue
		}
		addresses, _ := iface.Addrs()
		matchedScope := false
		for _, raw := range addresses {
			ip, _, err := net.ParseCIDR(raw.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			address, ok := netip.AddrFromSlice(ip.To4())
			if ok && policy.Contains(plan, address) {
				asset.Addresses = appendUnique(asset.Addresses, address.String())
				matchedScope = true
			}
		}
		if matchedScope && len(iface.HardwareAddr) > 0 {
			asset.MACs = appendUnique(asset.MACs, normalizeMAC(iface.HardwareAddr.String()))
		}
	}
	asset.Evidence = []model.Evidence{{Source: "local_interface", ObservedAt: observedAt, Observer: asset.ID}}
	return asset
}

func ReadNeighbors(plan model.Plan) ([]Neighbor, error) {
	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.Command("arp", "-a")
	} else if _, err := exec.LookPath("ip"); err == nil {
		command = exec.Command("ip", "neigh", "show")
	} else {
		return readProcARP(plan)
	}
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer la caché de vecinos: %w", err)
	}
	return parseNeighbors(string(output), plan), nil
}

func ProbeTargets(ctx context.Context, plan model.Plan, timeout time.Duration, concurrency int) ([]Reachability, error) {
	targets, err := policy.Targets(plan)
	if err != nil {
		return nil, err
	}
	if plan.Passive {
		return nil, nil
	}
	if concurrency < 1 {
		concurrency = 1
	}
	type indexed struct {
		index  int
		result Reachability
	}
	jobs := make(chan struct {
		index   int
		address netip.Addr
	})
	results := make(chan indexed, len(targets))
	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				result := ping(ctx, job.address.String(), timeout)
				results <- indexed{index: job.index, result: result}
			}
		}()
	}
	go func() {
		defer close(results)
		for index, address := range targets {
			select {
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return
			case jobs <- struct {
				index   int
				address netip.Addr
			}{index: index, address: address}:
			}
		}
		close(jobs)
		workers.Wait()
	}()
	ordered := make([]Reachability, len(targets))
	for item := range results {
		ordered[item.index] = item.result
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ordered, nil
}

func CheckServices(ctx context.Context, addresses []string, timeout time.Duration, concurrency int) []model.Service {
	ports := []int{22, 53, 80, 443, 445, 3389, 8080}
	type target struct {
		address string
		port    int
	}
	jobs := make(chan target)
	results := make(chan model.Service, len(addresses)*len(ports))
	if concurrency < 1 {
		concurrency = 1
	}
	var workers sync.WaitGroup
	for index := 0; index < concurrency; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range jobs {
				dialer := net.Dialer{Timeout: timeout}
				connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(item.address, strconv.Itoa(item.port)))
				if err != nil {
					continue
				}
				_ = connection.Close()
				results <- model.Service{Address: item.address, Port: item.port, Transport: "tcp", State: "open", ObservedAt: time.Now().UTC()}
			}
		}()
	}
	go func() {
		for _, address := range addresses {
			for _, port := range ports {
				jobs <- target{address: address, port: port}
			}
		}
		close(jobs)
		workers.Wait()
		close(results)
	}()
	services := make([]model.Service, 0)
	for service := range results {
		services = append(services, service)
	}
	return services
}

func ping(parent context.Context, address string, timeout time.Duration) Reachability {
	ctx, cancel := context.WithTimeout(parent, timeout+250*time.Millisecond)
	defer cancel()
	var arguments []string
	if runtime.GOOS == "windows" {
		arguments = []string{"-n", "1", "-w", strconv.Itoa(max(1, int(timeout.Milliseconds()))), address}
	} else {
		seconds := max(1, int((timeout+time.Second-1)/time.Second))
		arguments = []string{"-c", "1", "-W", strconv.Itoa(seconds), address}
	}
	started := time.Now()
	err := exec.CommandContext(ctx, "ping", arguments...).Run()
	return Reachability{Address: address, Reachable: err == nil, ProbeDurationMS: float64(time.Since(started).Microseconds()) / 1000}
}

func parseNeighbors(output string, plan model.Plan) []Neighbor {
	seen := map[string]bool{}
	var neighbors []Neighbor
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		var ipText, macText string
		for index, field := range fields {
			address, err := netip.ParseAddr(strings.Trim(field, "()"))
			if err == nil && address.Is4() {
				ipText = address.String()
				for _, candidate := range fields[index+1:] {
					if normalizeMAC(candidate) != "" {
						macText = candidate
						break
					}
				}
				break
			}
		}
		address, err := netip.ParseAddr(ipText)
		if err != nil || !policy.Contains(plan, address) {
			continue
		}
		mac := normalizeMAC(macText)
		if mac == "" || mac == "ff:ff:ff:ff:ff:ff" || seen[ipText+mac] {
			continue
		}
		seen[ipText+mac] = true
		neighbors = append(neighbors, Neighbor{Address: ipText, MAC: mac})
	}
	return neighbors
}

func readProcARP(plan model.Plan) ([]Neighbor, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("no hay una fuente de caché ARP compatible: %w", err)
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return parseNeighbors(string(content), plan), nil
}

func normalizeMAC(value string) string {
	value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
	parsed, err := net.ParseMAC(value)
	if err != nil || len(parsed) != 6 {
		return ""
	}
	return parsed.String()
}

func safeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)
	return strings.Trim(value, "-")
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
