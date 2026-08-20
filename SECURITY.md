# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/types`, please do not
open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days.
We ask that you give us reasonable time to address the issue before
public disclosure.

## Scope

This project is the protocol core of the AIC specification. Issues of
interest include:

- ASN.1 encoding/decoding correctness (resource exhaustion, malformed
  input handling)
- Capability matching logic (bypass, priority inversion, denial of
  service)
- Hash algorithm handling (length validation, algorithm confusion)
- Validation bypass in `ValidateAIC` and related functions

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.
