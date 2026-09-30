# Product Guidelines

- Map validation-method changes to the applicable CA/Browser Forum requirement and explicit acceptance criteria.
- Preserve public API types, random-value rules, domain authorization rules, and error semantics unless the specification changes them.
- Keep preparation and validation behavior distinct. Calling integrations own actions outside the library's documented scope.
- Persistent TXT validation checks evidence semantics and MPIC corroboration. The calling integration owns the documented 10-day reuse enforcement.
- Use controlled DNS and HTTP fixtures. Cover malformed input, expiry, mismatched evidence, and failed corroboration when relevant.
- Document library integration examples with synthetic data and explain responsibilities of the caller.
- Keep reference-app behavior separate from production-readiness claims.
