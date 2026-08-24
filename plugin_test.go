// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Copyright 2026 Jijie Wei
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"testing"
)

type mockPlugin struct {
	scheme string
}

func (m *mockPlugin) Scheme() string { return m.scheme }

func (m *mockPlugin) Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	return &PluginResult{Decision: PluginAllow, Reason: "mock ok"}, nil
}

func TestRegisterPlugin_Nil(t *testing.T) {
	ResetPlugins()
	err := RegisterPlugin(nil)
	if err == nil {
		t.Fatal("expected error for nil plugin")
	}
}

func TestRegisterPlugin_EmptyScheme(t *testing.T) {
	ResetPlugins()
	err := RegisterPlugin(&mockPlugin{scheme: ""})
	if err == nil {
		t.Fatal("expected error for empty scheme")
	}
}

func TestRegisterPlugin_Duplicate(t *testing.T) {
	ResetPlugins()
	if err := RegisterPlugin(&mockPlugin{scheme: "http"}); err != nil {
		t.Fatal(err)
	}
	err := RegisterPlugin(&mockPlugin{scheme: "http"})
	if err == nil {
		t.Fatal("expected error for duplicate scheme")
	}
}

func TestRegisterPlugin_Success(t *testing.T) {
	ResetPlugins()
	err := RegisterPlugin(&mockPlugin{scheme: "dtls"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFindPlugin_NotFound(t *testing.T) {
	ResetPlugins()
	_, err := findPlugin("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent plugin")
	}
}

func TestFindPlugin_Success(t *testing.T) {
	ResetPlugins()
	mp := &mockPlugin{scheme: "tcp"}
	if err := RegisterPlugin(mp); err != nil {
		t.Fatal(err)
	}
	p, err := findPlugin("tcp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Scheme() != "tcp" {
		t.Fatalf("expected scheme tcp, got %s", p.Scheme())
	}
}

func TestExecutePlugin_Success(t *testing.T) {
	ResetPlugins()
	if err := RegisterPlugin(&mockPlugin{scheme: "http"}); err != nil {
		t.Fatal(err)
	}
	cap := &Capability{SchemeId: "http", CapabilityId: "gateway:admin"}
	ctx := &PluginContext{
		Context: context.Background(),
		Target:  "/api/v1/test",
	}
	result, err := ExecutePlugin("http", cap, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != PluginAllow {
		t.Fatalf("expected allow, got %v", result.Decision)
	}
}

func TestExecutePlugin_NotFound(t *testing.T) {
	ResetPlugins()
	_, err := ExecutePlugin("quic", &Capability{}, &PluginContext{Context: context.Background()})
	if err == nil {
		t.Fatal("expected error for unregistered scheme")
	}
}

func TestResetPlugins(t *testing.T) {
	ResetPlugins()
	if err := RegisterPlugin(&mockPlugin{scheme: "tcp"}); err != nil {
		t.Fatal(err)
	}
	ResetPlugins()
	_, err := findPlugin("tcp")
	if err == nil {
		t.Fatal("expected error after reset")
	}
}

func TestRegistryRegisterAndExecute(t *testing.T) {
	reg := NewPluginRegistry()
	if err := reg.Register(&mockPlugin{scheme: "mysql"}); err != nil {
		t.Fatal(err)
	}
	cap := &Capability{SchemeId: "mysql", CapabilityId: "query"}
	ctx := &PluginContext{Context: context.Background()}
	result, err := reg.Execute("mysql", cap, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Decision != PluginAllow {
		t.Fatalf("expected allow, got %v", result.Decision)
	}
	if reg.Len() != 1 {
		t.Fatalf("expected Len 1, got %d", reg.Len())
	}
	if keys := reg.Keys(); len(keys) != 1 || keys[0] != "mysql" {
		t.Fatalf("unexpected keys: %v", keys)
	}
	reg.Reset()
	if reg.Len() != 0 {
		t.Fatalf("expected Len 0 after reset, got %d", reg.Len())
	}
}
