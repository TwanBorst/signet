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

## Choose the deployment mode

Signet automatically discovers all issuers within its configured scope,
including issuers created after startup. There is no per-issuer registration
list. Choose a mode in your complete Helm values file.

The default is **namespace mode**:

```yaml
deployment:
  mode: namespace
  namespace: team-a
```

This manages all `SignetIssuer` resources and their CertificateRequests in
`team-a`. Omit `deployment.namespace` or set it to `""` to use the Helm release
namespace. A custom namespace must already exist and may differ from the
namespace where Signet runs. Namespaced mode does not watch or manage any
`SignetClusterIssuer`, including requests referencing one from `team-a`.

For **cluster mode**:

```yaml
deployment:
  mode: cluster
  namespace: ""
```

This manages every `SignetIssuer` in every namespace and every
`SignetClusterIssuer`, together with their CertificateRequests throughout
the cluster. `deployment.namespace` must be empty in this mode.

The chart configures the runtime scope and RBAC, not the issuer resources
themselves. Both modes grant issuer reads and status updates, not issuer
creation, editing of `spec`, or deletion. Namespace mode uses a Role and
RoleBinding in the watched namespace; cluster mode uses a ClusterRole and
ClusterRoleBinding for workload access.

Both modes also need a small ClusterRole/ClusterRoleBinding for cert-manager's
synthetic `signers` approval authorization. cert-manager performs that check
without a namespace and supports a whole-issuer-type wildcard, not a
`<namespace>.*` wildcard. Namespace mode grants only
`signetissuers.signet.io/*`; the namespace Role prevents it from modifying
CertificateRequest status elsewhere. Cluster mode additionally grants
`signetclusterissuers.signet.io/*`. Installing even namespace mode therefore
requires an administrator able to provision these cluster-scoped resources
and Signet's CRDs.

The UI/API filters request history and actions to the configured scope in
namespace mode; records outside it remain stored but are not exposed or
processed. Use separate databases or database schemas for independent
deployments, and do not run overlapping deployment scopes against the same
requests. Deployment scope is not per-user authorization: all authenticated
Signet operators can act on its managed queue.

For non-Helm deployments, set `DEPLOYMENT_MODE` and, for namespace mode,
`WATCH_NAMESPACE`; see [runtime configuration](configuration.md).

### Migrating from the issuer allowlist

`issuerInstances` and `ISSUER_INSTANCES` have been removed. The chart and
runtime reject these settings rather than silently broadening access.
Remove them and explicitly choose a deployment mode before upgrading.
Do not reuse old Helm values containing `issuerInstances`; use
`--reset-values -f <complete-values-file>` if necessary to discard them.
Use cluster mode to continue managing both issuer kinds, or namespace mode
to restrict management to all namespaced issuers in one namespace.
Unlike the former exact-name allowlist, either mode automatically includes
new issuer names in its scope. Review issuer policies and who can create or
modify issuers and CertificateRequests before upgrading.

## Create the issuer resources

Save the following as `issuers.yaml`, replacing the names, namespace and
domains as needed. Ensure `team-a` exists before applying it.
The cluster issuer example requires cluster deployment mode; namespace mode
manages only the namespaced issuer example in its watched namespace.

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

If a request does not progress, check that its issuer is within the configured
deployment scope, that it exists in the correct resource scope, and that
all requested names satisfy the policy. Inspect CertificateRequest conditions
and Signet's queue and audit details for the failure reason. See
[operations](operations.md) for request lifecycle and recovery behavior.
