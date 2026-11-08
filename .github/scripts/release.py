"""Validate stable, forward-only releases from verified main commits."""

import json
import os
import re
import subprocess


def semver(tag):
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
    if not match:
        raise ValueError("Release tags must be stable SemVer: vMAJOR.MINOR.PATCH")
    return tuple(int(part) for part in match.groups())


def validate(tag, tags, on_main, verified):
    version = semver(tag)
    previous = []
    for existing in tags:
        if existing == tag:
            continue
        try:
            previous.append(semver(existing))
        except ValueError:
            continue
    if previous and version <= max(previous):
        raise ValueError("Release version must exceed all previous stable tags; older minor lines are not maintained")
    if not on_main:
        raise ValueError("Release commit must be on origin/main")
    if not verified:
        raise ValueError("Release commit needs a successful Verify push run on main; wait for CI and rerun this release")
    return ".".join(map(str, version))


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    tag = os.environ["GITHUB_REF_NAME"]
    semver(tag)
    sha = command("git", "rev-parse", f"{tag}^{{commit}}")
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", sha, "origin/main"], check=False
    )
    if ancestry.returncode not in (0, 1):
        raise RuntimeError("Cannot verify main ancestry")
    repository = os.environ["GITHUB_REPOSITORY"]
    runs = json.loads(command(
        "gh", "api",
        f"repos/{repository}/actions/workflows/verify.yml/runs?branch=main&event=push&head_sha={sha}&per_page=100",
    ))
    verified = any(
        run["head_sha"] == sha and run["head_branch"] == "main"
        and run["event"] == "push" and run["conclusion"] == "success"
        for run in runs["workflow_runs"]
    )
    version = validate(tag, command("git", "tag", "--list").splitlines(),
                       ancestry.returncode == 0, verified)
    releases = json.loads(command(
        "gh", "api", "--paginate", "--slurp", f"repos/{repository}/releases?per_page=100",
    ))
    if any(release["tag_name"] == tag for page in releases for release in page):
        raise ValueError("A GitHub Release already exists for this tag; publish a new version instead")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"version={version}\nsha={sha}\nimage=ghcr.io/{repository.lower()}\n")


if __name__ == "__main__":
    main()
