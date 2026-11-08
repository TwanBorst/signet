# Architecture

One binary serves the API, static UI from `/app/ui`, and cert-manager
controllers. It uses cert-manager CertificateRequests and external issuer
integration (issuer-lib v0.12.1), not native Kubernetes CSR signing. The
`signet.io/v1alpha1` API exposes namespaced `SignetIssuer` and cluster-scoped
`SignetClusterIssuer` objects with optional `caBundle` PEM and `dnsNames`
domain suffix allowlist and standard status conditions.

An authenticated operator handles an eligible request in the UI and uploads a
signed certificate; cert-manager manages the Certificate lifecycle and TLS
Secret. Signet reads CertificateRequests, writes their status and approval,
and accesses issuer status. It neither holds CA private keys nor generates
TLS Secrets. Signet's PostgreSQL database is independent of the workload and
stores durable audit/history indefinitely. Its availability gates audited
actions. The database and Kubernetes API cannot commit atomically together;
partial outcomes require reconciliation.

Manual signing remains pending until an operator completes it. In
[issuer-lib v0.12.1 `request_controller.go`](https://github.com/cert-manager/issuer-lib/blob/v0.12.1/controllers/request_controller.go),
the `isPending` branch precedes `pastMaxRetryDuration`: `PendingError` sets
Pending status and requeues without becoming terminal when that duration
expires. Signet returns Pending for database outages in `Sign`. Audit failures
in `IgnoreCertificateRequest` return a reconciliation error and retry with
backoff before reaching `Sign`, not a finite-duration signing error. Audited
actions remain blocked until persistence recovers.

Controller leader election is off. Multiple replicas can serve the API and
run controllers concurrently, using SQL row locks and idempotency rather than
a Kubernetes leader lease. Startup runs migrations under a database lock.
The ClusterIP service exposes port 8080 by default; `/healthz` and `/readyz`
are the liveness and readiness endpoints. Gateway API and Kuadrant are
optional integrations, not dependencies.

`/healthz` is liveness; `/readyz` checks database health. Controller events
use `events.k8s.io` create/patch permissions. No leader-election Lease
permissions are needed.

Exact signer approval names follow cert-manager's
[v1.20.5 webhook `signerNamesForAPIResource`](https://github.com/cert-manager/cert-manager/blob/v1.20.5/internal/webhook/admission/certificaterequest/approval/certificaterequest_approval.go):
`signetissuers.signet.io/<namespace>.<name>` for a namespaced issuer and
`signetclusterissuers.signet.io/<name>` for a cluster issuer. The namespace/name
slash spelling is not the webhook's signer format. Its `buildAttributes`
checks `approve` on `cert-manager.io` resource `signers`; the chart grants
only configured exact identities, without wildcard signer approvals.
