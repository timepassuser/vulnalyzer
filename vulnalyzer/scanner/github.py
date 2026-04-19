"""
vulnalyzer.scanner.github
==========================
Fetches repository metadata and raw manifest files from GitHub.

Supports:
  - Default-branch detection
  - Latest commit SHA retrieval (used as stable revision_id)
  - Raw file content fetching pinned to a specific commit SHA
  - Optional GitHub token auth (set GITHUB_TOKEN env var)
"""

from __future__ import annotations

import logging
import os
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
RAW_BASE   = "https://raw.githubusercontent.com"
TIMEOUT    = 12


def _headers() -> dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _get_json(url: str) -> dict | list | None:
    try:
        resp = requests.get(url, headers=_headers(), timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 403:
            logger.warning("GitHub rate limit hit or forbidden: %s", url)
        elif resp.status_code == 404:
            logger.debug("GitHub 404: %s", url)
        else:
            logger.warning("GitHub API %s → HTTP %d", url, resp.status_code)
    except requests.RequestException as exc:
        logger.error("GitHub request failed: %s – %s", url, exc)
    return None


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

def parse_github_url(url: str) -> tuple[str, str] | tuple[None, None]:
    """
    Extract (owner, repo) from a GitHub URL.

    Accepts:
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      github.com/owner/repo
    """
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    parts  = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return None, None
    owner = parts[0]
    repo  = parts[1].removesuffix(".git")
    return owner, repo


# ---------------------------------------------------------------------------
# Revision metadata
# ---------------------------------------------------------------------------

def get_revision(owner: str, repo: str) -> dict:
    """
    Return the latest revision metadata for the repo's default branch.

    Returns a dict:
        {
            "revision_id":   "<full commit SHA>",
            "revision_type": "git_commit",
            "branch_ref":    "<branch name>",
        }
    On any failure, revision_id is "unknown".
    """
    repo_data = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}")
    if not repo_data or not isinstance(repo_data, dict):
        return {"revision_id": "unknown", "revision_type": "unknown", "branch_ref": "main"}

    branch = repo_data.get("default_branch", "main")

    commit_data = _get_json(f"{GITHUB_API}/repos/{owner}/{repo}/commits/{branch}")
    if not commit_data or not isinstance(commit_data, dict):
        return {"revision_id": "unknown", "revision_type": "unknown", "branch_ref": branch}

    sha = commit_data.get("sha", "unknown")
    return {
        "revision_id":   sha,
        "revision_type": "git_commit",
        "branch_ref":    branch,
    }


# ---------------------------------------------------------------------------
# Raw file fetching
# ---------------------------------------------------------------------------

def fetch_file(owner: str, repo: str, revision_id: str, filename: str) -> str | None:
    """
    Fetch raw content of *filename* at *revision_id* from GitHub.
    Returns the text content or None if not found.
    """
    url = f"{RAW_BASE}/{owner}/{repo}/{revision_id}/{filename}"
    try:
        resp = requests.get(url, headers=_headers(), timeout=TIMEOUT)
        if resp.status_code == 200:
            return resp.text
        if resp.status_code not in (404,):
            logger.debug("fetch_file %s → HTTP %d", url, resp.status_code)
    except requests.RequestException as exc:
        logger.error("fetch_file failed: %s – %s", url, exc)
    return None
