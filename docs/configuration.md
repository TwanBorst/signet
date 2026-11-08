# Runtime configuration

The container serves both the Go API and the UI on port 8080. Docker builds the
React production assets and copies them into `/app/ui`; this path is fixed,
not configurable, and does not require a volume or a runtime frontend build.

These are all Signet application environment variables:

| Variable | Helm value | Required/default | Meaning |
| --- | --- | --- | --- |
| `DATABASE_URL` | `database.secretName` + `database.secretKey` | Required; key defaults to `url` | PostgreSQL connection URI from an existing Secret in the release namespace. Must use `sslmode=verify-full`. Configure `sslrootcert=/etc/signet/db-ca/ca.crt` when using the chart's CA mount. Never include credentials in values or logs. |
| `PUBLIC_ORIGIN` | `publicOrigin` | Required unless using `PUBLIC_ORIGINS` | Single exact HTTPS origin, without path/trailing slash, credentials, query or fragment. |
| `PUBLIC_ORIGINS` | `publicOrigins` | Required unless using `PUBLIC_ORIGIN` | Nonempty JSON array of exact HTTPS origins for mutation CSRF validation. No wildcards/duplicates; cannot be set together with `PUBLIC_ORIGIN`. Helm serializes the list automatically. |
| `AUTH_HEADER` | `authHeader` | `x-auth-request-email` | Custom `x-` header name containing exactly one verified ASCII email identity, supplied by the trusted authenticating upstream. |
| `ISSUER_INSTANCES` | `issuerInstances` | Required nonempty JSON array | Exact managed issuer identities, each with `kind`, `name`, `namespace`. Kind is `SignetIssuer` or `SignetClusterIssuer`; namespaced issuers need a namespace, cluster issuers require `""`. Only these identities receive scoped signer approval RBAC. |

For a deployment outside Helm, for example:

```text
ISSUER_INSTANCES=[{"kind":"SignetClusterIssuer","name":"manual","namespace":""},{"kind":"SignetIssuer","name":"team","namespace":"team-a"}]
PUBLIC_ORIGINS=["https://signet.example.com","https://signet.example.org"]
AUTH_HEADER=x-auth-request-email
```

`database.caSecretName` or `database.caConfigMap` optionally selects an existing
CA source in the release namespace; configure only one. `database.caKey`
selects its key (default `ca.crt`), always mounted as `/etc/signet/db-ca/ca.crt`.
This is independent of the database URL key. The application has no Kubernetes
Secret read permission: the kubelet supplies both the environment and volume.

See [getting started](getting-started.md) for complete Helm values and
[security](security.md) for upstream header replacement, CSRF and network
requirements. Kubernetes client authentication uses the normal in-cluster
ServiceAccount supplied by the chart; Signet does not introduce its own client
credential setting.
