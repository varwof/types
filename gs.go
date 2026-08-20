package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// KeyDerivationParams for session key derivation (v1.4).
type KeyDerivationParams struct {
	KDFAlgorithm asn1.ObjectIdentifier `asn1:"objectidentifier"`
	KeyLength    int                   `asn1:"default:32"`
	Salt         []byte                `asn1:"octet"`
	Info         string                `asn1:"utf8,optional"`
}

// GatewaySessionExtension corresponds to the Gateway Session extension (OID 1.3.6.1.4.1.66257.1.5).
// Note: This OID is historical/pre-v1.5. The v1.5+ PrincipalAuthorization uses OID .1.2.
// GatewaySessionExtension is kept as a runtime type (lib/gs.go) for non-AIC session scenarios.
type GatewaySessionExtension struct {
	Version       int                   `asn1:"default:1"`
	MaxConcurrent int                   `asn1:"optional,omitempty"`
	HardTimeout   int                   `asn1:"optional,omitempty"`
	AllowedCIDRs  []string              `asn1:"optional,omitempty"`
	MaxRetries    int                   `asn1:"optional,omitempty"`
	KeyDerivation []KeyDerivationParams `asn1:"optional,explicit,tag:0"`
}

// ParseGatewaySessionExtension parses the Gateway Session extension from a certificate.
func ParseGatewaySessionExtension(cert *x509.Certificate) (*GatewaySessionExtension, error) {
	if cert == nil {
		return nil, nil
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDGatewaySession) {
			var gs GatewaySessionExtension
			if _, err := asn1.Unmarshal(ext.Value, &gs); err != nil {
				return nil, fmt.Errorf("gateway session: unmarshal failed: %w", err)
			}
			return &gs, nil
		}
	}
	return nil, nil
}

// MaxConcurrentLimit returns the max concurrent connection limit.
func (g *GatewaySessionExtension) MaxConcurrentLimit() int {
	if g == nil {
		return 0
	}
	return g.MaxConcurrent
}

// HardTimeoutLimit returns the session hard timeout in seconds.
func (g *GatewaySessionExtension) HardTimeoutLimit() int {
	if g == nil {
		return 0
	}
	return g.HardTimeout
}

// CIDRAllowed checks if the given IP is within allowed CIDRs (empty list = unrestricted).
func (g *GatewaySessionExtension) CIDRAllowed(ip string) bool {
	if g == nil || len(g.AllowedCIDRs) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range g.AllowedCIDRs {
		_, cidrNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if cidrNet.Contains(parsed) {
			return true
		}
	}
	return false
}

// MaxRetriesLimit returns the max retries limit.
func (g *GatewaySessionExtension) MaxRetriesLimit() int {
	if g == nil {
		return 0
	}
	return g.MaxRetries
}

// ValidateKeyDerivation validates key derivation parameter size constraints.
func (g *GatewaySessionExtension) ValidateKeyDerivation() error {
	if g == nil {
		return nil
	}
	for i, kd := range g.KeyDerivation {
		if len(kd.Salt) > 0 && (len(kd.Salt) < 16 || len(kd.Salt) > 32) {
			return fmt.Errorf("keyDerivation[%d].salt length %d: must be 16-32 bytes", i, len(kd.Salt))
		}
	}
	return nil
}

var _ = pkix.Extension{}
