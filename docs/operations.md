# Operations

## Database and upgrades

Keep PostgreSQL independent from the release. Provision persistent storage,
monitor database capacity and availability, connection counts, backups, audit
growth, controller errors, readiness and certificate expiration. Audit and
history are retained indefinitely: budget for sustained growth and backup
costs. Do not silently prune audit records.

Before every deployment or upgrade, take and verify a restorable PostgreSQL
backup, for example `pg_dump --format=custom --file=signet.dump "$DATABASE_URL"`
from a secure environment. Protect the file and credentials. Regularly restore
into an isolated database with `pg_restore`, check audit/history and exercise
the application against the restore; document and test recovery objectives.
Backups of the database do not replace Kubernetes Secret backups.

Each application container runs migrations on startup with a database lock so
concurrent starts serialize them. For rolling upgrades, deploy only versions
whose old and new binaries are compatible with the migration: use additive
schema changes first, keep old-version compatibility while replicas overlap,
and defer destructive changes until old versions are gone. Verify the actual
release's migration compatibility before rollout; locking alone does not make
an incompatible migration safe. Roll back binaries only when the migrated
schema supports the old version. Back up before changing CRDs as well; Helm
does not upgrade CRDs in `crds/`.

## Chart resource names

The chart uses the release name alone when it already contains the chart name
`signet`; otherwise it appends `-signet`. For example:

| Helm release | Deployment, Service, ServiceAccount and NetworkPolicy name |
| --- | --- |
| `signet` | `signet` |
| `prod-signet` | `prod-signet` |
| `signet-prod` | `signet-prod` |
| `prod` | `prod-signet` |

Names are truncated to 63 characters and trailing hyphens are removed.
RBAC names additionally include the release namespace to distinguish
cluster-scoped permissions for releases in different namespaces; signer
approval RBAC also adds `-approve`. These suffixes remain even if the
namespace equals the resource name. Deployment ServiceAccount references and
RBAC subjects and role references use the same generated names. Pod labels,
Deployment selectors and Service/NetworkPolicy selectors are unchanged.

Earlier charts always appended the chart name, producing names such as
`signet-signet`. Upgrading a release whose name already contains `signet`
therefore replaces its named resources rather than renaming them in place.
Plan a maintenance window: stop the old Deployment before upgrading to avoid
overlapping Deployments with identical selectors, and expect Service
connectivity to be interrupted. Update HTTPRoute backends, other external
Service references, DNS names, monitoring targets and operational commands to
the new names. Review rendered manifests and the Helm upgrade diff first.
The external database, issuer resources and cert-manager-managed TLS Secrets
are not renamed by this helper.

## Recovery, deletion and renewal

Operator denial or cancellation of an already Approved CertificateRequest is
stored as `denied` or `cancelled` in Signet. The controller reports
`Ready=False` with reason `Failed` through issuer-lib `PermanentError`, not
the Kubernetes `Denied` condition: approval conditions are immutable and
Approved/Denied are mutually exclusive. cert-manager handles retries by
creating a new CertificateRequest with a new UID; do not try to reset approval
conditions or reuse the terminal request.

On database loss, stop changes, restore a verified backup, restart the
workload, and reconcile Kubernetes CertificateRequests and audit records. A
database rollback can lose recent records while Kubernetes objects remain:
investigate the gap and do not assume cross-system atomicity. Restoring a
release or deleting its workload does not delete the external database.
Protect and separately back up the cert-manager TLS Secrets and issuer objects.

cert-manager drives renewals and creates new CertificateRequests. Operators
must complete manual signing and upload before expiration; monitor pending
requests and renew well ahead of expiry. Existing TLS Secret certificates
remain in use until cert-manager replaces them with a successfully issued
renewal. Deleting a Certificate, Secret, issuer or release can disrupt this
flow; understand cert-manager's configured ownership/garbage-collection
behavior and retain old Secret material during recovery. Deletion of
Kubernetes objects does not erase retained database history.
