// Copyright 2026 Jijie Wei
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"context"
	"fmt"
	"sync"
)

// PluginDecision represents the decision result after plugin execution.
type PluginDecision int

// PluginAllow/Deny/Bypass are plugin decision constants.
const (
	PluginAllow PluginDecision = iota
	PluginDeny
	PluginBypass
)

// PluginResult is the return result after plugin execution.
type PluginResult struct {
	Decision PluginDecision
	Reason   string
	Metadata map[string]string
}

// HTTPFacts carries per-request HTTP facts for capability plugins.
type HTTPFacts struct {
	Method  string
	Path    string
	Query   map[string][]string
	Headers map[string]string
}

// PluginContext is the context during plugin execution.
type PluginContext struct {
	Context  context.Context
	AIC      *AIC
	UserPerm *UserPermission
	Target   string
	ClientCN string
	Roles    []string
	AgentId  string

	// Optional HTTP request facts, populated by HTTP-facing gateways
	// so that capability plugins can evaluate request conditions
	// (method/path/query/headers). Zero values mean "not provided".
	Method  string
	Path    string
	Query   map[string][]string
	Headers map[string]string
}

// CapabilityPlugin is the interface for all capability plugins.
type CapabilityPlugin interface {
	Scheme() string
	Execute(cap *Capability, ctx *PluginContext) (*PluginResult, error)
}

// PluginRegistry manages plugin registration and lookup.
type PluginRegistry struct {
	mu      sync.RWMutex
	plugins map[string]CapabilityPlugin
}

// NewPluginRegistry creates a new empty registry.
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{plugins: make(map[string]CapabilityPlugin)}
}

var globalRegistry = NewPluginRegistry()

// RegisterPlugin registers a plugin in the global registry.
func RegisterPlugin(p CapabilityPlugin) error {
	return globalRegistry.Register(p)
}

// findPlugin looks up a registered plugin by schemeID.
func findPlugin(schemeID string) (CapabilityPlugin, error) {
	return globalRegistry.Find(schemeID)
}

// ExecutePlugin is a convenience wrapper for findPlugin + Execute.
func ExecutePlugin(schemeID string, cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	return globalRegistry.Execute(schemeID, cap, ctx)
}

// ResetPlugins clears the global registry (testing only).
func ResetPlugins() {
	globalRegistry.Reset()
}

// Register registers a plugin to this instance.
func (r *PluginRegistry) Register(p CapabilityPlugin) error {
	if p == nil {
		return fmt.Errorf("plugin: nil plugin")
	}
	s := p.Scheme()
	if s == "" {
		return fmt.Errorf("plugin: empty scheme")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.plugins[s]; exists {
		return fmt.Errorf("plugin: scheme %q already registered", s)
	}
	r.plugins[s] = p
	return nil
}

// Find looks up a registered plugin by schemeID.
func (r *PluginRegistry) Find(schemeID string) (CapabilityPlugin, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[schemeID]
	if !ok {
		return nil, fmt.Errorf("plugin: no plugin for scheme %q", schemeID)
	}
	return p, nil
}

// Execute is a convenience wrapper for Find + Execute.
func (r *PluginRegistry) Execute(schemeID string, cap *Capability, ctx *PluginContext) (*PluginResult, error) {
	p, err := r.Find(schemeID)
	if err != nil {
		return nil, err
	}
	return p.Execute(cap, ctx)
}

// Reset clears the registry.
func (r *PluginRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins = make(map[string]CapabilityPlugin)
}

// Len returns the number of registered plugins.
func (r *PluginRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}

// Keys returns the scheme list of all registered plugins.
func (r *PluginRegistry) Keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.plugins))
	for k := range r.plugins {
		keys = append(keys, k)
	}
	return keys
}
