# Getting started

Install cert-manager 1.20 or newer, a cluster with a NetworkPolicy-enforcing
CNI, and an external PostgreSQL database. The database is independent of the
release and retains issuance history and audit records indefinitely. Provision
its least-privilege role and an external Secret in Signet's namespace with a
`url` key containing the connection URL; `database.secretKey` can select a
different key. Never put the password in Helm values.
`DATABASE_URL` strictly requires `sslmode=verify-full`; other modes are rejected.
Supply an external provider CA using `database.caSecretName` or
`database.caConfigMap` (not both); `database.caKey` defaults to `ca.crt`.
The chart mounts it read-only at `/etc/signet/db-ca/ca.crt`, referenced by
`sslrootcert` in the URL. The hostname in the URL must match the server
certificate. Arrange DNS, egress, access to the Kubernetes API and a trusted
authenticating proxy before installation.

Example values (replace all placeholders and use a built/published image):

```yaml
image:
  repository: registry.example.com/signet
  tag: "0.1.0"
database:
  secretName: signet-db
  secretKey: url
  caSecretName: postgres-provider-ca
publicOrigin: https://signet.example.com
authHeader: x-auth-request-email
issuerInstances:
  - kind: SignetClusterIssuer
    name: manual
    namespace: ""
  - kind: SignetIssuer
    name: team
    namespace: team-a
networkPolicy:
  ingressFrom:
    - namespaceSelector:
        kubernetes.io/metadata.name: gateway-system
      podSelector:
        app: trusted-proxy
  postgres:
    cidrs: ["192.0.2.10/32"]
    port: 5432
  apiServer:
    cidrs: ["192.0.2.20/32"]
    port: 443
```

Save as `signet-values.yaml`, set real addresses/labels, then run:

For two or more domains sharing the same backend, replace `publicOrigin` with:

```yaml
publicOrigins:
  - https://signet.example.com
  - https://signet.example.org
```

Configure either `publicOrigin` or `publicOrigins`, not both. Values must be
exact HTTPS origins (optional port, no trailing slash, path or wildcard).
Route both the UI and `/api` on each domain to the same Signet Service through
trusted authenticating proxies. Apply the identity-header and network
protections to every entry point. No UI rebuild, cross-domain API URL or CORS
configuration is needed; requests, decisions and history are shared.
For deployments without Helm, set `PUBLIC_ORIGINS` to a nonempty JSON array,
for example `["https://signet.example.com","https://signet.example.org"]`.
Existing `PUBLIC_ORIGIN` configurations remain supported; do not set both
environment variables.

Create the external Secrets in namespace `signet` first. This illustrates the
URI and CA file path; use your secret-management tooling rather than committing
real credentials. Percent-encode reserved characters in URI credentials.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: signet-db
  namespace: signet
type: Opaque
stringData:
  url: "postgresql://signet:REPLACE_PASSWORD@db.example.com:5432/signet?sslmode=verify-full&sslrootcert=/etc/signet/db-ca/ca.crt"
---
apiVersion: v1
kind: Secret
metadata:
  name: postgres-provider-ca
  namespace: signet
type: Opaque
stringData:
  ca.crt: |
    REPLACE_WITH_PROVIDER_CA_PEM
```

The CA Secret mount is optional if the provider CA is already trusted by the
image and the URL references an available trust file. Mounting Secrets does
not grant the application Kubernetes API Secret read permissions.

```sh
helm upgrade --install signet ./charts/signet --namespace signet \
  --create-namespace -f signet-values.yaml
```

Ingress requires **both** namespace and pod labels. PostgreSQL may instead
use a paired `networkPolicy.postgres.selector.namespaceSelector` and
`podSelector`. Set the DNS selectors and API server port/CIDRs for your CNI
and cluster topology. Depending on the CNI, Service IP translation, host
networking, NodeLocal DNS and API-server routing may require different CIDRs
or additional infrastructure rules. NetworkPolicy allows traffic; it does not
authenticate it. Only a ClusterIP Service is created; expose it through a
properly secured proxy as described in [security](security.md).

`networkPolicy.enabled` defaults to `true`. Set it to `false` only for an
isolated smoke test: no chart NetworkPolicy is rendered or enforced, and the
peer/CIDR requirements are skipped. This is not a secure production setting
and provides no network-isolation assurance.

Create an issuer matching the configured identity:

```yaml
apiVersion: signet.io/v1alpha1
kind: SignetClusterIssuer
metadata:
  name: manual
spec:
  dnsNames: [example.com]
  # caBundle: |
  #   -----BEGIN CERTIFICATE-----
  #   ...
  #   -----END CERTIFICATE-----
```

`SignetIssuer` is namespaced; configure the corresponding namespace in
`issuerInstances`. `SignetClusterIssuer` is cluster-scoped and must use an
empty namespace. `dnsNames` is an optional DNS domain suffix allowlist;
`caBundle` is optional inline PEM. Configure the instances before creating
CertificateRequests and update the release when changing them. The chart
requires explicit issuer identities, an HTTPS origin, a database Secret name,
trusted ingress peers, PostgreSQL egress and API-server CIDRs.

The application container performs database migrations automatically at
startup; see [operations](operations.md) before upgrading. Helm installs CRDs
from `crds/` on initial install but does not upgrade or delete them; manage
CRD upgrades deliberately.
