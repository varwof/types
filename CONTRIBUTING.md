# Contributing

Thanks for considering contributing to `varwof/types`.

## Reporting Issues

- Use the GitHub issue tracker for bugs, feature requests, and
  questions.
- Include the Go version, operating system, and a minimal reproducer
  when reporting a bug.
- For security vulnerabilities, do NOT open a public issue; see
  [SECURITY.md](SECURITY.md).

## Development Setup

```bash
go test ./...
go vet ./...
```

The module has zero external dependencies; the standard library
suffices.

## Code Style

- Run `gofmt` on all changed files.
- Keep the zero-dependency constraint: no new external imports.
- All exported identifiers need a doc comment.
- Tests are required for new behavior. The project values boundary
  tests and round-trip (encode/decode) tests.

## Commit Messages

Follow the conventional commit style:

- `feat: ...` new functionality
- `fix: ...` bug fixes
- `docs: ...` documentation
- `refactor: ...` code restructuring without behavior change
- `test: ...` tests

## Pull Requests

1. Fork the repository and create a feature branch.
2. Implement the change with tests.
3. Run `gofmt`, `go vet ./...`, and `go test ./...`.
4. Open a pull request describing the change and its motivation.
5. Keep changes focused; split unrelated changes into separate PRs.

## Contributor License Agreement

By submitting a pull request, you agree to sign the
[Individual CLA](https://github.com/varwof/dev-docs/blob/main/CLA-INDIVIDUAL.md)
(or [Corporate CLA](https://github.com/varwof/dev-docs/blob/main/CLA-CORPORATE.md)
for employer-sponsored contributions). The CLA grants the project a
permissive copyright and patent license for your contributions, while
you retain ownership of your code.

## Specification Alignment

This library implements the AIC protocol structures from
[draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/).
Changes to protocol types or encoding MUST stay aligned with the
specification; non-protocol additions (utilities, helpers, docs) are
welcome without specification changes.

## License

By contributing, you agree that your contributions are licensed under
the Apache-2.0 license, as described in [LICENSE](LICENSE).
