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
- `aicjwt` subpackage: AIC-JWT (`draft-wei-aic-jwt-00`) claims model,
  JWS sign/verify, capability matching (draft Section 6.2), constraint
  evaluation and the 11-step validation pipeline

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

// Validate an AIC-JWT (github.com/varwof/types/aicjwt)
import aicjwt "github.com/varwof/types/aicjwt"
dec, err := aicjwt.Validate(token, aicjwt.VerifyOptions{ /* ... */ })
```

## License

Apache-2.0
