# Releases

Signet uses stable SemVer tags `vMAJOR.MINOR.PATCH`. There are no maintenance
branches: all releases come from `main`, and only the newest major/minor line
receives patch releases. For example, after `v0.2.0`, do not release `v0.1.4`.
Versions must increase numerically beyond every previous stable tag.
Prerelease/build-metadata tags are not supported by this initial strategy.

Verification runs once per PR update, and on pushes to `main`, not on feature
branch pushes or tag pushes. New updates cancel obsolete verification runs.
Tag releases reuse the successful `main` push verification for that exact
commit rather than repeating the matrix. The release gate rejects tags outside
`main` and commits without successful verification. If CI is still running,
wait for it to succeed and rerun the failed release workflow.

## Publish

Merge the reviewed changes to `main`, wait for **Verify** to succeed, and tag
that exact commit:

```sh
git fetch origin main --tags
git tag -a v0.1.0 origin/main -m "Signet 0.1.0"
git push origin v0.1.0
```

The version in the tag is authoritative. The workflow sets the chart `version`
and `appVersion` when packaging; no version-bump commit is necessary. The source
chart version is a development baseline. The chart defaults its image tag to
its packaged `appVersion`, so every release deploys the matching container.
An explicit `image.tag` override still works.

The workflow publishes using `GITHUB_TOKEN`, without long-lived registry
credentials:

- Container: `ghcr.io/twanborst/signet:0.1.0` (linux/amd64).
- OCI chart: `oci://ghcr.io/twanborst/charts/signet`, version `0.1.0`.
- GitHub Release `v0.1.0`: generated change notes, chart archive, image digest
  and `SHA256SUMS`; marked latest only after both packages publish successfully.

## CVE and SBOM reports

Verification and release workflows use pinned Trivy tooling to generate:

- `image.cdx.json`: CycloneDX SBOM of the final container, including OS packages
  and discoverable Go modules.
- `source.cdx.json`: source dependency inventory, including npm lockfile
  dependencies that are not discoverable in the compiled UI. Development/test
  dependencies are included; it is not a list of runtime-only frontend packages.
- `image-vulnerabilities.json` / `.sarif` and
  `source-vulnerabilities.json` / `.sarif`: known vulnerability findings at all
  reported severities, including findings with no available fix.
- `scanner-version.txt` and `scanned-image.txt`: scanner/database metadata and
  the inspected image reference.

**Policy is report-only:** known CVEs do not block verification or publication,
but scanner/database/download errors fail the workflow. No vulnerability
exceptions or blanket suppression list is applied. The existing npm audit check
also reports findings without a severity gate (`--audit-level=none`).
PR/main reports are retained
as Actions artifacts for 30 days, release reports for 90 days. GitHub Releases
also attach the reports and SBOMs with checksums for durable download.
SARIF is supplied as a file, not uploaded to GitHub code scanning; this works
without additional security-event permissions or code-scanning entitlements.

Release image reports inspect the published immutable digest, not a mutable
tag. Reports are snapshots of the vulnerability database at scan time, not a
guarantee of safety or continuous monitoring. Source and image scans run locally
in the runner; no source upload to a scanning service is configured. The Helm
chart packages configuration, not runtime dependencies; the matching image and
source SBOMs cover its application, not cert-manager or other platform services.
SBOMs are release assets, not signed attestations or OCI referrers.

The release image is uploaded before its digest scan; scanner failures can
therefore leave an image without a completed release. The partial-publication
recovery procedure below still applies. Review reports before deployment.

Only exact version tags are published; there are no mutable `latest` or minor
aliases. Release jobs are serialized. Treat tags and published artifacts as
immutable: do not move tags, delete version tags or rebuild them with different
source. Configure repository tag rulesets for `v*` to restrict tag creation,
updates and deletion to trusted maintainers. Protect `main` with the Verify
check and review requirements.

GHCR packages can initially be private. A maintainer must configure **both**
the container and chart package visibility/access in GitHub package settings
for the intended consumers. Public source visibility alone does not ensure
anonymous pulls. Do not use deployment values containing secrets as release
assets.

Publishing GHCR artifacts and a GitHub Release is not an atomic operation.
If publication fails partway through, fix the cause and rerun the same tag
before creating a newer tag. Completed GitHub Releases cannot be republished
by this workflow; use a new version for corrections. Do not rerun an older
release after advancing the version. A package pushed before a failure may
exist without a GitHub Release; a retry can overwrite that incomplete
publication, so do not deploy artifacts until its GitHub Release exists.

## Install

For private packages, authenticate Docker and Helm with a suitable read-only
package token. For public packages no registry login is needed.

```sh
helm upgrade --install signet oci://ghcr.io/twanborst/charts/signet \
  --version 0.1.0 --namespace signet --create-namespace -f signet-values.yaml
```

Use the database, authentication, issuer and NetworkPolicy values described in
[getting started](getting-started.md). Remove development `image.repository`
and `image.tag` overrides to use the packaged defaults. Pin a chart version;
review [operations](operations.md) before upgrading. To download the OCI
package without installing:

```sh
helm pull oci://ghcr.io/twanborst/charts/signet --version 0.1.0
docker pull ghcr.io/twanborst/signet:0.1.0
```
