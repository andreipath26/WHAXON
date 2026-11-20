"""Fail closed before publishing a tagged release."""
from __future__ import annotations

import json
import os
import subprocess
from urllib.request import Request, urlopen


def verify_main_ancestry(commit_sha: str) -> None:
    """Require the tagged commit to be reachable from the fetched main branch."""
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit_sha, "FETCH_HEAD"],
        check=True,
    )


def has_green_ci_for_exact_commit(
    repository: str,
    commit_sha: str,
    token: str,
    *,
    opener=urlopen,
) -> bool:
    """Return whether a completed successful CI run exists for this exact SHA."""
    request = Request(
        f"https://api.github.com/repos/{repository}/actions/runs"
        f"?head_sha={commit_sha}&per_page=100",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with opener(request, timeout=20) as response:
        runs = json.load(response)["workflow_runs"]
    return any(
        run.get("name") == "CI"
        and run.get("head_sha") == commit_sha
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        for run in runs
    )


def main() -> None:
    repository = os.environ["GITHUB_REPOSITORY"]
    commit_sha = os.environ["GITHUB_SHA"]
    token = os.environ["GH_TOKEN"]

    subprocess.run(["git", "fetch", "--no-tags", "origin", "main"], check=True)
    verify_main_ancestry(commit_sha)
    if not has_green_ci_for_exact_commit(repository, commit_sha, token):
        raise SystemExit(
            f"Refusing release: no completed green CI run for exact commit {commit_sha}."
        )
    print(f"Exact release commit {commit_sha} is on main and has green CI.")


if __name__ == "__main__":
    main()
