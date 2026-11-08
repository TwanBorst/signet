# Signet's issuer-lib patch

This directory retains the Apache-2.0 source from cert-manager/issuer-lib
**v0.12.1**, commit `5899c1ac7a11b6d0e895b18082048ee33aa70431`.
Its LICENSE and original notices are retained.

Signet adds the observed CertificateRequest UID and resourceVersion to
issuer-lib's status apply patches. Unpatched v0.12.1 applies status by namespace
and name alone. If a request is deleted and recreated during reconciliation,
that could send the old result to the new UID. The preconditions also prevent
an approval/status update racing with a certificate-delivery patch.

Only the CertificateRequest status patch generator and its call site are
changed; a regression test asserts both fields are serialized. The native
Kubernetes CSR controller remains disabled in Signet.

When upgrading issuer-lib, review this change explicitly. Do not remove the
local Go module replacement until equivalent upstream UID/version protection
has been verified with the deletion/recreation race test.
