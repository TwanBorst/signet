# Signet

A cert-manager external issuer for certificates signed outside the cluster.
cert-manager retains private keys, creates CertificateRequests, and updates TLS
Secrets. Signet operators download approved PEM CSRs, obtain signatures
externally, and upload the certificate and optional chain.

The Go controller uses cert-manager's issuer-lib; the React/TypeScript interface
provides an authenticated queue, certificate history, and durable PostgreSQL
audit. Only explicitly configured `signet.io` issuer instances are managed.
There is no native Kubernetes CSR workflow.

## Deployment

Build the combined backend/UI image with `docker build -t signet:local .`.
Provision PostgreSQL separately, configure verified TLS, install cert-manager
1.20 or later, and deploy `charts/signet`. The chart does not install an
authentication proxy, a database, Gateway API, or Kuadrant.

See [getting started](docs/getting-started.md),
[security boundary](docs/security.md), [operations](docs/operations.md),
and [architecture](docs/architecture.md). Optional Gateway examples are in
[`examples/gateway`](examples/gateway).

Tagged releases publish a versioned [container image](https://ghcr.io/twanborst/signet),
an OCI chart at `oci://ghcr.io/twanborst/charts/signet`, and a GitHub Release
with the chart archive and checksums. See [release strategy](docs/releases.md)
for SemVer, publishing and installation instructions.

**Do not expose the Service directly to users.** An upstream authentication
service must strip and replace the configured identity header. All authenticated
users may act. Audit-dependent operations fail closed if PostgreSQL is
unavailable. Kubernetes and database administrators are trusted.

## Development

Go 1.26 and Node 24 are the build tools. Run `go test ./...` and, in `ui`,
`npm ci`, `npm test -- --run`, and `npm run build`. Database tests require
`SIGNET_TEST_DATABASE_URL` pointing at an isolated disposable PostgreSQL
database; tests create and remove uniquely named schemas.

See [verification](docs/verification.md) for the compatibility matrix,
isolated end-to-end runner, and remaining deployment limitations. No private
keys are retained in the Signet database or served by its API.

Signet's controller/API wiring is adapted from
[sample-external-issuer](https://github.com/cert-manager/sample-external-issuer)
and uses [issuer-lib](https://github.com/cert-manager/issuer-lib) v0.12.1 with
a [minimal UID/version safety patch](third_party/issuer-lib/SIGNET-PATCH.md).
Upstream Apache-2.0 notices are retained in [LICENSE](LICENSE) and [NOTICE](NOTICE).
