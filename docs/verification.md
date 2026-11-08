# Verification

Verified locally on 2026-11-08 using Docker Desktop and a dedicated kind cluster
(`kind` 0.33.0, Kubernetes 1.36.4). The user's configured cluster was not used.

| Component | Evidence |
| --- | --- |
| Go 1.26 backend | Unit/database/controller/API tests and Go race detector |
| PostgreSQL 17 | Concurrent first-start migrations, checksum/version rejection, immutable UID, racing decisions, rollback when audit writes fail |
| React/TypeScript | 36 fetch-mocked tests, strict typecheck and production build; dependency audit clean |
| cert-manager 1.20.5 | Real approval, manual issuance, restart during wait, manual renewal and retained old TLS Secret, both issuer scopes |
| cert-manager 1.21.3 | Same real-cluster end-to-end scenarios after upgrade |
| Helm | Rendering, lint, invalid configuration rejection; two real Ready replicas with verified PostgreSQL TLS |
| Real chart HTTP API | Scoped approval, audited CSR download, private-key rejection, CSRF/identity rejection, upload, duplicate conflict and TLS Secret issuance |
| Browser | Desktop request details and mobile queue render checked against the live isolated deployment |
| Gateway API examples | Both Kustomize layers render; manifests target the pinned version documented with the examples |

The actual cert-manager tests prove that cert-manager creates and retains keys,
that no final TLS Secret exists before the initial manual signature, that the
old certificate and key remain untouched during a renewal's manual wait, and
that issuance replaces the certificate and rotates the key. They trigger the
same Issuing condition as `cmctl renew`, not an artificial TLS Secret edit.
Deleting a Kubernetes request does not delete its historical database CSR.
Tests explicitly check that private keys are absent from database snapshots.

Controller tests assert that a year-old pending request still returns
issuer-lib's `PendingError`. In issuer-lib v0.12.1,
`controllers/request_controller.go` handles this error before its finite
`MaxRetryDuration` check. Signet also uses PendingError for unavailable durable
state/audit, rather than allowing a long manual wait to turn a later database
outage into a terminal error.

Signet retains a minimal issuer-lib v0.12.1 fork because upstream's request
status patches are addressed by name/namespace only. The local patch carries
the observed UID and resourceVersion. A fork regression test checks serialized
preconditions; a real API deletion/recreation race verifies that the old
certificate cannot be applied to a replacement request with the same name.
See [patch maintenance](../third_party/issuer-lib/SIGNET-PATCH.md).

## Reproduce

With Docker, Helm and kubectl installed:

```powershell
.\tests\verify.ps1
```

The script creates its own randomly named kind cluster and PostgreSQL container,
uses an explicit kubeconfig on every command, runs the two cert-manager versions,
and removes only its own containers, cluster and credentials. Go caches and test
output remain under `.verification`/Docker cache volumes. It requires image
downloads, enough Docker memory, and permissions to create local containers.
The database URL in this harness uses plaintext **only inside disposable Docker
test networks**. The production binary rejects anything other than verified TLS.

For targeted tests, set `SIGNET_TEST_DATABASE_URL` to a disposable database and
run `go test -race ./internal/...`. Without this environment variable, database
tests explicitly skip; that is not a passing database verification.
End-to-end tests additionally require `SIGNET_E2E_KUBECONFIG` with a
`kind-signet-*` context, Signet CRDs, and installed cert-manager.

## Environment limitations

No production identity provider, database provider, backup service, GatewayClass
implementation or Kuadrant installation was available. Kustomize render tests
do not establish reconciliation or enforcement by those components. Scheduled
time-based renewal, multi-node network partitions, production load, and releases
later than the two versions listed above have not been exercised.

The full issuance tests run the controller in a test process with disposable
cluster-admin credentials; they do not on their own prove Pod RBAC or NetworkPolicy
enforcement. Deployment administrators must separately verify the trusted-proxy
boundary, database backups/restoration and egress configuration.

## Real chart runtime

The chart was additionally deployed in the disposable cluster with two replicas,
an external PostgreSQL 17 container reached through a Service/EndpointSlice, a
dedicated test CA, and `sslmode=verify-full`. Both replicas became Ready with zero
restarts; health and database readiness endpoints returned 200. The final image
also completed a rolling restart against the existing schema.

Impersonated SelfSubjectAccessReviews confirmed approval of the two exact
configured signer identities, rejection of unconfigured identities and
incorrectly slash-spelled namespaced identities, permission to patch request
status and create events, and denial of TLS Secret writes and Lease creation.
NetworkPolicy was deliberately disabled in this isolated kind smoke test, so
this is not a NetworkPolicy enforcement result.
