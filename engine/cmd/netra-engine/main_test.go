package main

import (
	"strings"
	"testing"

	"github.com/Roger08G/netra/engine/internal/policy"
)

func TestDecodeStrictRejectsUnknownFields(t *testing.T) {
	var input policy.PlanInput
	err := decodeStrict([]byte(`{"scope":["192.168.1.0/24"],"unexpected":true}`), &input)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestDecodeStrictRejectsTrailingDocument(t *testing.T) {
	var input policy.PlanInput
	err := decodeStrict([]byte(`{"scope":["192.168.1.0/24"]} {}`), &input)
	if err == nil {
		t.Fatal("expected trailing document error")
	}
}
