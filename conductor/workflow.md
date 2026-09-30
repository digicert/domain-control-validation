# Development Workflow

## Plan and Implement

- Check `git status --short` and preserve unrelated work.
- Define a focused specification and plan with the applicable validation requirements, API compatibility, non-goals, risks, and verification. Obtain approval before implementation.
- Track tasks with `[ ]`, `[~]`, and `[x]` in `plan.md`, alongside verification evidence and blockers.
- Match existing library API, package, exception, and JUnit patterns. Prefer focused tests that prove validation semantics.
- Pause for approval when requirements, dependencies, or scope materially change.

## Verify

| Scope | Command |
| --- | --- |
| Focused library test | `mvn -pl library test -Dtest=TestClass` |
| Library unit suite | `mvn -pl library test` |
| Reactor build | `mvn clean install` |
| Integration lifecycle | `mvn clean verify` |
| Library coverage | `mvn -pl library clean verify -Pcoverage` |

Run the library test suite first for core semantics. Follow [example-app/README.md](../example-app/README.md) and the module POM before running integration tests, which use MySQL and PowerDNS through Docker Compose. Record infrastructure failures separately from validation failures.

Use existing coverage and CI checks. Verify documentation links and examples for documentation-only changes.

## Review and Delivery

- Review each acceptance criterion and public API impact against test evidence.
- Stage, commit, push, create a PR, merge, release, or revert only after an explicit request for that action. Obtain approval of the exact commit message and external-facing text before publication.
- Include the Jira key where available and keep tooling attribution out of commit messages and PR text.
- Preserve unrelated changes and avoid direct pushes to `main` or `master`.
- Keep summaries in track documents. Git notes and automatic checkpoint commits are not required.
