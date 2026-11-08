# Optional Gateway examples

These examples are separate from the chart. Install a Gateway API implementation
and its externally configured GatewayClass. For a pinned standard CRD bundle,
see [Gateway API v1.4.0](https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/standard-install.yaml);
check your controller's compatibility before installing it. cert-manager 1.20+
and Signet's CRDs/controller must also be installed. Replace the GatewayClass,
domains, namespaces, service name and issuer reference before applying.
Install a `SignetClusterIssuer` named `manual` and include it in the chart's
`issuerInstances`. Issue the certificates via Signet before expecting TLS to
become ready. The Secret references are in the Gateway namespace; cert-manager,
not Signet, generates and stores their private keys.

`kubectl kustomize examples/gateway/base` renders a Gateway with separate
apex and wildcard listeners and Certificates. Each listener's certificate is
shared by routes attached to that listener, not generated per route. Label only
trusted route namespaces `gateway-access=signet`; review the sample Namespace
resources before applying them to existing namespaces. Gateway and route
hostnames must intersect. The wildcard TLS certificate covers one label, e.g.
`signet.example.com`, not `a.b.example.com` or the apex. Strict route
admission/hostname governance is out of scope; namespace labels alone are not
tenant isolation.

`kubectl kustomize examples/gateway/kuadrant` replaces the explicit
Certificates with a Kuadrant TLSPolicy and adds an AuthPolicy. This is an
optional illustration, not a complete authentication deployment: replace the
OIDC issuer, configure and verify the identity proxy/header injection and
stripping described in [security](../../docs/security.md), and verify that the
selected Gateway integration enforces both policies before exposing Signet.
The AuthPolicy alone does **not** establish Signet's trusted email header.
Never run the explicit Certificate resources and TLSPolicy for the same
listener Secrets simultaneously. See Kuadrant's
[TLSPolicy reference](https://docs.kuadrant.io/1.5.x/kuadrant-operator/doc/reference/tlspolicy/)
and [AuthPolicy reference](https://docs.kuadrant.io/1.5.x/kuadrant-operator/doc/reference/authpolicy/).
