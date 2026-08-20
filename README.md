# Varwof Types

Shared type definition library providing AIC, Capability, Principal and other core types for the Varwof PKI suite.

## Features

- Zero external dependencies, pure standard library
- AIC (Agent Identity Certificate) extension structure and validation
- Capability definitions with glob pattern matching
- PrincipalUid principal identifier with SPKI key hash
- DelegationAuthorization delegation authorization
- PrincipalAuthorization with delegation policy
- GatewaySessionExtension for execution constraints
- Hash algorithm support (SHA-2/SHA-3 family)

## Installation

```bash
go get github.com/varwof/types
```

## Usage

```go
import pki "github.com/varwof/types"

// Parse AIC from certificate
aic, err := pki.ParseAIC(cert)

// Validate AIC
err = pki.ValidateAIC(aic)

// Match capability with glob pattern
matched := pki.MatchCapability("oracle/mysql:query:users", "oracle/*:query:*")
```

## License

Apache-2.0
