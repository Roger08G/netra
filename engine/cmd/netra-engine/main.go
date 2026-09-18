package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/Roger08G/netra/engine/internal/policy"
	"github.com/Roger08G/netra/engine/internal/runner"
)

const protocolVersion = "1.0"
const productVersion = "1.0.0"

type request struct {
	ProtocolVersion string          `json:"protocol_version"`
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	Payload         json.RawMessage `json:"payload"`
}

type event struct {
	ProtocolVersion string `json:"protocol_version"`
	RequestID       string `json:"request_id"`
	Type            string `json:"type"`
	Timestamp       string `json:"timestamp"`
	Payload         any    `json:"payload"`
}

type capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return err
		}
		return fmt.Errorf("se esperaba una orden JSON por stdin")
	}
	var message request
	if err := decodeStrict(scanner.Bytes(), &message); err != nil {
		return fmt.Errorf("orden JSON no válida: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	emit := func(eventType string, payload any) {
		_ = encoder.Encode(event{ProtocolVersion: protocolVersion, RequestID: message.ID, Type: eventType, Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Payload: payload})
	}
	fail := func(err error) error {
		emit("run.failed", map[string]string{"message": err.Error()})
		return err
	}
	if message.ProtocolVersion != protocolVersion {
		return fail(fmt.Errorf("versión de protocolo no compatible: %q", message.ProtocolVersion))
	}
	if message.ID == "" || message.Type == "" {
		return fail(fmt.Errorf("id y type son obligatorios"))
	}
	switch message.Type {
	case "doctor":
		emit("doctor.completed", doctorPayload())
		return nil
	case "plan.create":
		var input policy.PlanInput
		if err := decodeStrict(message.Payload, &input); err != nil {
			return fail(fmt.Errorf("payload de plan no válido: %w", err))
		}
		plan, err := policy.CreatePlan(input)
		if err != nil {
			return fail(err)
		}
		emit("plan.completed", map[string]any{"plan": plan})
		return nil
	case "scan.execute":
		var input runner.ScanInput
		if err := decodeStrict(message.Payload, &input); err != nil {
			return fail(fmt.Errorf("payload de scan no válido: %w", err))
		}
		_, err := runner.Scan(ctx, input, emit)
		if err != nil {
			return fail(err)
		}
		return nil
	default:
		return fail(fmt.Errorf("tipo de orden desconocido: %q", message.Type))
	}
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("se encontró contenido JSON adicional")
		}
		return err
	}
	return nil
}

func doctorPayload() map[string]any {
	capabilities := []capability{
		{Name: "engine", Available: true, Detail: runtime.Version() + " / " + runtime.GOOS + "/" + runtime.GOARCH},
		{Name: "snmpv3", Available: true, Detail: "USM authPriv, consultas GET/GETBULK de solo lectura"},
		lookup("ping", "descubrimiento ICMP de bajo impacto"),
		lookup("arp", "lectura de la caché local IPv4"),
		lookup("nmap", "integración opcional; aún no utilizada por esta entrega"),
		lookup("dumpcap", "captura opcional para una futura fuente LLDP"),
	}
	return map[string]any{
		"protocol_version": protocolVersion,
		"product_version":  productVersion,
		"capabilities":     capabilities,
		"notes": []string{
			"SNMPv3 consulta IF-MIB, BRIDGE-MIB, Q-BRIDGE-MIB y LLDP-MIB; la compatibilidad final depende del agente del equipo.",
			"Netra no implementa SNMP SET y no escribe secretos en eventos ni artefactos.",
		},
	}
}

func lookup(name, detail string) capability {
	path, err := exec.LookPath(name)
	if err != nil {
		return capability{Name: name, Available: false, Detail: detail}
	}
	return capability{Name: name, Available: true, Detail: path}
}
