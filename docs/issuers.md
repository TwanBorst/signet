# Issuer configuration

Signet provides two cert-manager external issuer resources in
`signet.io/v1alpha1`. Both use the same policy fields and manual signing
workflow: an operator downloads a CSR, obtains a signature outside the
cluster, and uploads the signed certificate and optional chain through Signet.
Neither resource stores a CA private key or requires a CA signing Secret.

## Choosing a scope

| Kind | Resource scope | Where Certificates can reference it |
| --- | --- | --- |
| `SignetIssuer` | Namespaced; set `metadata.namespace` | Only in the issuer's namespace |
| `SignetClusterIssuer` | Cluster-scoped; omit `metadata.namespace` | Any namespace |

Use a namespaced issuer for a team's namespace and a cluster issuer for a
shared policy. A domain allowlist restricts names, not which namespaces may
use a cluster issuer. Use Kubernetes RBAC and your cluster's certificate
request policies to control who can create requests.

## Register the managed identities

Before creating certificate requests, include every issuer Signet should
manage in the Helm release's values:

```yaml
issuerInstances:
  - kind: SignetClusterIssuer
    name: manual
    namespace: ""
  - kind: SignetIssuer
    name: team
    namespace: team-a
```

The kind, name and namespace must match exactly. Cluster issuers require
`namespace: ""` in this list, even though their Kubernetes resources omit
`metadata.namespace`. Namespaced issuers use their own namespace, which need
not be the namespace where Signet is deployed.

This setting configures the managed identities and their scoped signer
approval RBAC; it does not create issuer resources. Upgrade the release using
your complete values file when changing the list. Helm replaces lists, so
retain all identities that should remain managed. For non-Helm deployments,
see [`ISSUER_INSTANCES`](configuration.md).

## Create the issuer resources

Save the following as `issuers.yaml`, replacing the names, namespace and
domains as needed. Ensure `team-a` exists before applying it.

```yaml
apiVersion: signet.io/v1alpha1
kind: SignetClusterIssuer
metadata:
  name: manual
spec:
  dnsNames:
    - example.com
  # Optional trust anchor(s); replace the placeholder with actual PEM.
  # caBundle: |
  #   -----BEGIN CERTIFICATE-----
  #   ...
  #   -----END CERTIFICATE-----
---
apiVersion: signet.io/v1alpha1
kind: SignetIssuer
metadata:
  name: team
  namespace: team-a
spec:
  dnsNames:
    - team-a.example.com
  # caBundle: |
  #   -----BEGIN CERTIFICATE-----
  #   ...
  #   -----END CERTIFICATE-----
```

```sh
oc apply -f issuers.yaml
```

The examples use OpenShift's `oc`; `kubectl` works with the same arguments.
Install Signet's CRDs first, as described in [getting started](getting-started.md).

## Policy fields

Both fields are optional and have identical behavior for both issuer kinds.

### `spec.dnsNames`

A list of allowed DNS suffixes, not a list of certificates to create.
An entry of `example.com` allows `example.com`, `app.example.com`,
`app.team.example.com` and `*.example.com`, but not `otherexample.com`.
Multiple suffixes are alternatives: a requested name must match at least one.

Use lowercase DNS suffixes without a wildcard prefix or trailing dot in the
allowlist itself. Wildcards are allowed in requested certificate names only
as a single leading `*.`. The policy checks every DNS SAN and any nonempty
Common Name. With a nonempty allowlist, requests containing IP, email or URI
SANs are rejected.

Omitting `dnsNames` or setting it to `[]` removes the DNS suffix restriction
and does not prohibit IP, email or URI SANs. Other request and certificate
validation still applies. Configure an explicit allowlist when domain
restrictions are required.

### `spec.caBundle`

An inline string containing one or more PEM-encoded CA certificates, not
base64 and not a Secret reference:

```yaml
spec:
  dnsNames:
    - example.com
  caBundle: |
    -----BEGIN CERTIFICATE-----
    ...replace with your actual CA certificate...
    -----END CERTIFICATE-----
```

Each certificate must be a CA with valid basic constraints, certificate-signing
key usage and a supported, safe public key. Include only public certificates,
never private keys. When a bundle is configured, uploaded certificates must
chain to one of these trust anchors; supply any required intermediates with
the upload.

Without a bundle, Signet still validates the certificate against the request
and checks a supplied chain, but does not establish trust against a configured
CA. Configure `caBundle` when you need to enforce which CA signed the result.
This bundle is independent of the database TLS CA settings.

## Reference an issuer from a Certificate

Always set `issuerRef.group: signet.io` and the exact issuer kind and name.
There is no namespace field in `issuerRef`.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: shared-app
  namespace: team-a
spec:
  secretName: shared-app-tls
  dnsNames:
    - app.example.com
  issuerRef:
    group: signet.io
    kind: SignetClusterIssuer
    name: manual
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: team-app
  namespace: team-a
spec:
  secretName: team-app-tls
  dnsNames:
    - app.team-a.example.com
  issuerRef:
    group: signet.io
    kind: SignetIssuer
    name: team
```

cert-manager creates CertificateRequests and manages the resulting TLS Secrets
in the Certificate's namespace. Creating a Certificate does not complete
issuance: an operator must complete the external signing and upload workflow.

## Inspect configuration and requests

```sh
oc get signetclusterissuers.signet.io
oc get signetissuers.signet.io -n team-a
oc describe signetclusterissuer manual
oc describe signetissuer team -n team-a
oc get certificates,certificaterequests -n team-a
```

If a request does not progress, check that its issuer reference matches a
registered identity, that the issuer exists in the correct scope, and that
all requested names satisfy the policy. Inspect CertificateRequest conditions
and Signet's queue and audit details for the failure reason. See
[operations](operations.md) for request lifecycle and recovery behavior.
