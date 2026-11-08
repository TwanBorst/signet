# Security and trust

Signet trusts an email identity header supplied by an authenticating proxy.
`AUTH_HEADER` defaults to `x-auth-request-email`; custom names must use the
`x-` prefix. Its value must be email-only ASCII: one plain mailbox, not a
display name, address list or Unicode address.
The proxy **must strip all client-supplied copies** of the configured header,
authenticate the user, and replace it with exactly one verified email value.
Missing, malformed or duplicate identity headers must fail closed. Verify
these behaviors end-to-end including case variations, multiple header lines
and comma-separated values. Restrict direct access to the ClusterIP and pods:
otherwise a client can forge its identity. NetworkPolicy only works when
enforced by the CNI, and other policies may add access; review them and
host-network traffic. Health probes and other paths must not bypass the trust
boundary for application requests.

All authenticated users can act on requests: Signet does not provide per-user
roles. Restrict membership at the proxy. Mutating browser requests require
`X-Signet-CSRF: 1` and a strict `Origin` match to the configured HTTPS allowlist
(`PUBLIC_ORIGINS`, or legacy `PUBLIC_ORIGIN`); protect
the proxy from rewriting or accepting untrusted Origin values. Use HTTPS at
the external endpoint. Kubernetes and database administrators are trusted;
they can bypass application controls or alter state and audit records.

Allowlisted domains are equally trusted entry points to the same requests and
audit history. Configure only domains you control, without wildcards. Each
domain must authenticate users and strip/replace the identity header; preserve
the browser's Origin header rather than rewriting it to an allowed value.
Serve the UI and proxy `/api` on each domain to the same backend. Signet does
not enable cross-origin CORS or share authentication cookies between domains;
sessions are managed by each upstream. An origin allowlist does not enforce
Host routing or replace the authentication/network trust boundary.

Audit writes fail closed: do not approve or issue if audit persistence fails.
PostgreSQL and Kubernetes are not a distributed atomic transaction; reconcile
and investigate partial failures. Signet stores neither private keys nor TLS
Secrets in the database or logs. cert-manager owns generated private keys and
Secrets. Protect those Secrets with Kubernetes RBAC and encryption at rest.
The chart does not grant Secret access or native `certificates.k8s.io` CSR
permissions. Signer approvals are limited to configured exact issuer
identities; review any other cert-manager approver policies independently.

`DATABASE_URL` strictly requires `sslmode=verify-full` with a trusted externally supplied provider CA
and matching server hostname. Keep credentials in an external Secret, grant
the database role only the access required to operate and migrate Signet's
database, and protect the credentials and CA Secret/ConfigMap from untrusted changes.
Encrypt database disks, backups and transport; restrict backup access.
