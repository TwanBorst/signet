# Agent guidance

## Project

Signet is a cert-manager external issuer for certificates signed outside the
cluster. Operators download approved CSRs and upload signed certificates;
cert-manager manages private keys, CertificateRequests, and TLS Secrets.
Signet does not implement a native Kubernetes CSR workflow.

The Go binary runs the controller, HTTP API, and static React UI. PostgreSQL
stores request history and durable audit records. Key directories:

- `api/v1alpha1`: Signet issuer API types.
- `cmd/signet`: startup, configuration, and server wiring.
- `internal/controller`: issuer and CertificateRequest reconciliation and scope.
- `internal/httpapi`: authenticated API and request actions.
- `internal/pki`: certificate and CSR validation.
- `internal/store`: PostgreSQL access and embedded, versioned migrations.
- `ui`: React/TypeScript frontend.
- `charts/signet`: Helm deployment, RBAC, network policy, and CRDs.
- `tests`: Helm checks and isolated integration/e2e verification.
- `third_party/issuer-lib`: local issuer-lib fork; see its `SIGNET-PATCH.md`.

## Invariants

- Never store or log private keys or database passwords. cert-manager owns TLS
  private keys and Secrets; Signet does not need Secret access.
- The authenticating proxy must strip and replace the configured identity
  header. All authenticated users can act; there are no per-user roles.
  Mutating browser requests require the CSRF header and an exact configured
  HTTPS origin. Do not weaken these boundaries.
- Audit-dependent actions fail closed when PostgreSQL is unavailable. Database
  and Kubernetes writes are not atomic together; preserve reconciliation and
  retry behavior for partial failures.
- Production PostgreSQL connections require `sslmode=verify-full` and a trusted
  CA. Migrations run at startup under a transaction-scoped advisory lock.
  Preserve migration checksums and concurrency safeguards; do not modify an
  already-applied migration.
- Namespace mode watches one namespace and excludes cluster issuers. Cluster
  mode manages both issuer kinds. Keep watches, controllers, chart RBAC, and
  documentation consistent when changing scope behavior.
- CertificateRequest status patches must include the observed UID and
  resourceVersion. Do not remove the issuer-lib replacement without verifying
  equivalent upstream protection and the deletion/recreation race test.

## Development and verification

Go 1.26 and Node 24 are the project toolchains. Run focused tests for the
changed area and expand as needed:

- Backend: `go test ./...`.
- Frontend, from `ui`: `npm ci`, `npm test -- --run`, `npm run build`.
- Helm: `.\tests\helm-origins.ps1`.
- Release scripts: `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`.
- Full isolated PostgreSQL and cert-manager matrix: `.\tests\verify.ps1`
  (requires Docker, Helm, kubectl, and image downloads).

Database tests require `SIGNET_TEST_DATABASE_URL` pointing to an isolated,
disposable PostgreSQL database; they create and remove uniquely named schemas.
Without it, database tests skip. See `docs/verification.md` for prerequisites,
the e2e harness, and verification limitations.

## Commits and releases

- **All commits must have GitHub-verified signatures.** Use a configured signing
  key or GitHub's signed commit API; verify the result on GitHub. Do not rewrite
  published history without explicit authorization.
- Releases use increasing stable SemVer tags from verified `main` commits.
  The release workflow packages the matching chart and image and generates
  release notes. The tag is authoritative; chart source versions are a
  development baseline. Follow `docs/releases.md` before publishing.

For further context, consult `README.md`, `docs/architecture.md`,
`docs/security.md`, `docs/configuration.md`, `docs/operations.md`,
`docs/issuers.md`, and `docs/releases.md`.
