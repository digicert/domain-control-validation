# Domain Control Validation Library

This library implements DigiCert's domain control validation process under the CA/Browser Forum Baseline Requirements. Each supported method provides preparation and validation steps through the library's request and response APIs.

## Modules

- `library`: validation methods, reusable APIs, DNS/HTTP clients, and unit tests.
- `example-app`: reference REST integration and full-flow integration tests. It is a reference application rather than a production service.

## Priorities

- Implement the applicable validation-method requirements with testable outcomes.
- Preserve public request, response, and integration contracts.
- Keep library responsibilities distinct from calling applications, including email delivery and evidence-reuse policy.

See [README.md](../README.md), [README-details.md](../README-details.md), and [reference-app documentation](../example-app/README.md).
