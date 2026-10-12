#!/usr/bin/env python3
"""
=====================================================================================
SCRIPT NAME:      gh-traffic.py
VERSION:          1.0

DESCRIPTION:
    Pull GitHub repository traffic statistics for one or more repositories:

      - Clones (total, unique, and per-day breakdown)
      - Views  (total, unique, and per-day breakdown)
      - Top referring sites
      - Top popular content (paths)
      - Repository metadata (stars, forks, watchers, issues, size, etc.)
      - Release download counts (total + latest)
      - Auto-discovery of repositories owned by a user/org
      - Spike / anomaly detection on the 14-day window
      - Clone-to-view ratio + "likely bot traffic" heuristic

    GitHub's traffic API retains only the last 14 days of data. This script
    optionally archives every response it fetches into a local JSON file per
    repository, so you can build a permanent history that outlives the
    14-day window.

    A TTL cache is supported: if an archive entry is newer than the cache
    TTL, the cached snapshot is reused instead of hitting the API.

    Requires a token with push (write) access to the repository. Fine-grained
    tokens need "Administration" repository permissions (read).

USAGE
-----
    export GITHUB_TOKEN="ghp_..."
    python src/automation/gh-traffic.py --repo your-username/your-repo-name
    python src/automation/gh-traffic.py --repo your-username/your-repo-name --repo your-username/another-repo
    python src/automation/gh-traffic.py --file repos.txt
    python src/automation/gh-traffic.py --file repos.txt --json > traffic.json
    python src/automation/gh-traffic.py --file repos.txt --csv traffic.csv
    python src/automation/gh-traffic.py --repo your-username/your-repo-name --archive ~/.gh-traffic
    python src/automation/gh-traffic.py --repo your-username/your-repo-name --history
    python src/automation/gh-traffic.py --discover your-username
    python src/automation/gh-traffic.py --discover your-username --include-forks --include-archived
    python src/automation/gh-traffic.py --repo your-username/your-repo-name --cache-ttl 3600
    python src/automation/gh-traffic.py --repo your-username/your-repo-name --refresh
    python src/automation/gh-traffic.py --self-test

REQUIREMENTS
------------
    - Python 3.8+
    - A GitHub token with push access to the repositories you want to audit
    - No third-party packages (uses urllib from the stdlib)

Copyright (c) 2026 Jericho Crosby (Chalwk)
LICENSE: MIT
=====================================================================================
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import json
import os
import random
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple


__version__ = "1.1.1"


# Enable ANSI escape sequences on Windows 10 console
if os.name == "nt":
    os.system("")

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ============================================================================
# COLORS / OUTPUT HELPERS
# ============================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"
    ALERT = "\033[1;97;41m"


USE_COLOR = False


def paint(text: Any, code: str) -> str:
    text = str(text)
    return f"{code}{text}{C.RESET}" if USE_COLOR and code else text


def pad(text: Any, width: int, code: str = "", align: str = "l") -> str:
    s = str(text)
    s = s.rjust(width) if align == "r" else s.ljust(width)
    return paint(s, code)


def warn(msg: str, code: str = C.YELLOW) -> None:
    print(paint(msg, code), file=sys.stderr)


# ============================================================================
# CONFIG
# ============================================================================
CONFIG: Dict[str, Any] = {
    "api_base": "https://api.github.com",
    "user_agent": f"gh-traffic/{__version__} (https://github.com/Chalwk/python-scripts)",
    "timeout": 30.0,
    "retries": 3,
    "backoff": 1.0,
    "max_backoff": 60.0,
    "workers": 4,
    # Default archive directory (None = ~/.cache/gh-traffic)
    "archive_dir": None,
    # Repositories to check when none are passed on the command line.
    # Format: "owner/name"
    "repos": [
        # "your-username/your-repo-name",
    ],
    "redact": False,
    # Fetch repository metadata (stars/forks/issues/releases).
    # Set to False (or pass --no-repo-stats) to save API calls.
    "repo_stats": True,
    # Cache TTL in seconds. 0 disables caching.
    "cache_ttl": 0,
    # Analysis thresholds
    "spike_z_threshold": 2.0,
    "bot_ratio_threshold": 100,  # clones per unique visitor considered suspicious
    "bot_unique_view_floor": 5,  # below this many uniques, warn
}


# ============================================================================
# ERRORS
# ============================================================================
class GitHubError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        retryable: bool = False,
        fatal: bool = False,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.fatal = fatal
        self.retry_after = retry_after


# ============================================================================
# DATA MODELS
# ============================================================================
@dataclass
class DailyPoint:
    date: str
    count: int
    uniques: int


@dataclass
class Referrer:
    referrer: str
    count: int
    uniques: int


@dataclass
class PopularPath:
    path: str
    title: str
    count: int
    uniques: int


@dataclass
class RepoStats:
    """Metadata about the repository itself (not traffic)."""

    fetched: bool = False
    stars: int = 0
    forks: int = 0
    watchers: int = 0
    subscribers: int = 0
    open_issues: int = 0
    size_kb: int = 0
    language: Optional[str] = None
    license: Optional[str] = None
    archived: bool = False
    disabled: bool = False
    is_fork: bool = False
    default_branch: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    pushed_at: Optional[str] = None
    release_count: int = 0
    release_downloads: int = 0
    latest_release_tag: Optional[str] = None
    latest_release_downloads: int = 0
    latest_release_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stars": self.stars,
            "forks": self.forks,
            "watchers": self.watchers,
            "subscribers": self.subscribers,
            "open_issues": self.open_issues,
            "size_kb": self.size_kb,
            "language": self.language,
            "license": self.license,
            "archived": self.archived,
            "disabled": self.disabled,
            "is_fork": self.is_fork,
            "default_branch": self.default_branch,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "pushed_at": self.pushed_at,
            "release_count": self.release_count,
            "release_downloads": self.release_downloads,
            "latest_release_tag": self.latest_release_tag,
            "latest_release_downloads": self.latest_release_downloads,
            "latest_release_at": self.latest_release_at,
        }


@dataclass
class TrafficSnapshot:
    repo: str
    fetched_at: str
    clones_total: int
    clones_uniques: int
    clones_daily: List[DailyPoint]
    views_total: int
    views_uniques: int
    views_daily: List[DailyPoint]
    referrers: List[Referrer]
    paths: List[PopularPath]
    stats: RepoStats = field(default_factory=RepoStats)


@dataclass
class RepoSummary:
    repo: str
    clones_total: int = 0
    clones_uniques: int = 0
    views_total: int = 0
    views_uniques: int = 0
    referrer_count: int = 0
    path_count: int = 0
    stars: int = 0
    forks: int = 0
    open_issues: int = 0
    downloads: int = 0
    error: Optional[str] = None
    cached: bool = False


@dataclass
class Analysis:
    clone_view_ratio: float = 0.0
    clone_spikes: List[Tuple[str, int, float]] = field(default_factory=list)
    view_spikes: List[Tuple[str, int, float]] = field(default_factory=list)
    peak_clone_day: Optional[DailyPoint] = None
    peak_view_day: Optional[DailyPoint] = None
    likely_bot_traffic: bool = False
    low_traffic: bool = False
    notes: List[str] = field(default_factory=list)


# ============================================================================
# ARCHIVE
# ============================================================================
def default_archive_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "gh-traffic"


def archive_path(archive_dir: Path, repo: str) -> Path:
    safe = repo.replace("/", "_").replace("\\", "_")
    return archive_dir / f"{safe}.json"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class Archive:
    """Load, merge, and save traffic snapshots per repository."""

    def __init__(self, root: Path, enabled: bool = True) -> None:
        self.root = root
        self.enabled = enabled
        self._lock = threading.Lock()

    def load(self, repo: str) -> Dict[str, Any]:
        if not self.enabled:
            return {}
        path = archive_path(self.root, repo)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def is_fresh(self, repo: str, ttl_seconds: float) -> bool:
        if not self.enabled or ttl_seconds <= 0:
            return False
        data = self.load(repo)
        updated = _parse_iso(data.get("updated"))
        if not updated:
            return False
        age = (datetime.now(timezone.utc) - updated).total_seconds()
        return 0 <= age < ttl_seconds

    def load_snapshot(self, repo: str) -> Optional[TrafficSnapshot]:
        """Reconstruct the last TrafficSnapshot from the archive."""
        if not self.enabled:
            return None
        data = self.load(repo)
        last = data.get("last_snapshot")
        if not isinstance(last, dict):
            return None
        try:
            stats_raw = last.get("stats") or {}
            stats = RepoStats(
                fetched=True,
                **{
                    k: v
                    for k, v in stats_raw.items()
                    if k in RepoStats.__dataclass_fields__
                },
            )
            return TrafficSnapshot(
                repo=data.get("repo", repo),
                fetched_at=str(
                    last.get("fetched_at") or data.get("updated") or _iso_now()
                ),
                clones_total=int(last.get("clones_total", 0) or 0),
                clones_uniques=int(last.get("clones_uniques", 0) or 0),
                clones_daily=[
                    DailyPoint(**p)
                    for p in (last.get("clones_daily") or [])
                    if isinstance(p, dict)
                ],
                views_total=int(last.get("views_total", 0) or 0),
                views_uniques=int(last.get("views_uniques", 0) or 0),
                views_daily=[
                    DailyPoint(**p)
                    for p in (last.get("views_daily") or [])
                    if isinstance(p, dict)
                ],
                referrers=[
                    Referrer(**r)
                    for r in (last.get("referrers") or [])
                    if isinstance(r, dict)
                ],
                paths=[
                    PopularPath(**p)
                    for p in (last.get("paths") or [])
                    if isinstance(p, dict)
                ],
                stats=stats,
            )
        except (TypeError, ValueError):
            return None

    def merge(self, snapshot: TrafficSnapshot) -> Dict[str, Any]:
        """Merge a new snapshot into the archive for this repo."""
        if not self.enabled:
            return {}
        existing = self.load(snapshot.repo)

        clones = existing.get("clones") or {}
        for point in snapshot.clones_daily:
            prev = clones.get(point.date)
            # Keep the highest count seen for a given day.
            if prev is None or point.count >= int(prev.get("count", 0)):
                clones[point.date] = {"count": point.count, "uniques": point.uniques}

        views = existing.get("views") or {}
        for point in snapshot.views_daily:
            prev = views.get(point.date)
            if prev is None or point.count >= int(prev.get("count", 0)):
                views[point.date] = {"count": point.count, "uniques": point.uniques}

        # Referrers and paths are rolling 14-day aggregates. Store each
        # snapshot keyed by fetch date so we can see changes over time.
        referrer_snapshots = existing.get("referrer_snapshots") or []
        referrer_snapshots.append(
            {
                "date": snapshot.fetched_at[:10],
                "data": [
                    {"referrer": r.referrer, "count": r.count, "uniques": r.uniques}
                    for r in snapshot.referrers
                ],
            }
        )
        # Keep only the most recent 90 snapshots.
        referrer_snapshots = referrer_snapshots[-90:]

        path_snapshots = existing.get("path_snapshots") or []
        path_snapshots.append(
            {
                "date": snapshot.fetched_at[:10],
                "data": [
                    {
                        "path": p.path,
                        "title": p.title,
                        "count": p.count,
                        "uniques": p.uniques,
                    }
                    for p in snapshot.paths
                ],
            }
        )
        path_snapshots = path_snapshots[-90:]

        # Metadata history (stars/forks/etc). Keeps a rolling record so
        # we can chart growth over time even though the traffic API
        # itself has no long-term history.
        stats_history = existing.get("stats_history") or []
        if snapshot.stats.fetched:
            stats_history.append(
                {
                    "date": snapshot.fetched_at[:10],
                    "stars": snapshot.stats.stars,
                    "forks": snapshot.stats.forks,
                    "watchers": snapshot.stats.watchers,
                    "open_issues": snapshot.stats.open_issues,
                    "release_downloads": snapshot.stats.release_downloads,
                }
            )
            stats_history = stats_history[-365:]

        merged: Dict[str, Any] = {
            "repo": snapshot.repo,
            "updated": snapshot.fetched_at,
            "clones": clones,
            "views": views,
            "referrer_snapshots": referrer_snapshots,
            "path_snapshots": path_snapshots,
            "stats_history": stats_history,
            "last_snapshot": {
                "fetched_at": snapshot.fetched_at,
                "clones_total": snapshot.clones_total,
                "clones_uniques": snapshot.clones_uniques,
                "clones_daily": [
                    {"date": p.date, "count": p.count, "uniques": p.uniques}
                    for p in snapshot.clones_daily
                ],
                "views_total": snapshot.views_total,
                "views_uniques": snapshot.views_uniques,
                "views_daily": [
                    {"date": p.date, "count": p.count, "uniques": p.uniques}
                    for p in snapshot.views_daily
                ],
                "referrers": [
                    {"referrer": r.referrer, "count": r.count, "uniques": r.uniques}
                    for r in snapshot.referrers
                ],
                "paths": [
                    {
                        "path": p.path,
                        "title": p.title,
                        "count": p.count,
                        "uniques": p.uniques,
                    }
                    for p in snapshot.paths
                ],
                "stats": snapshot.stats.to_dict(),
            },
        }
        return merged

    def save(self, repo: str, payload: Dict[str, Any]) -> None:
        if not self.enabled or not payload:
            return
        path = archive_path(self.root, repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path: Optional[str] = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=str(path.parent), prefix=".gh-traffic-", suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            os.replace(tmp_path, path)
        except OSError as exc:
            warn(f"Could not write archive for {repo}: {exc}", C.YELLOW)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    def list_repos(self) -> List[str]:
        if not self.enabled or not self.root.exists():
            return []
        repos: List[str] = []
        for p in sorted(self.root.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("repo"):
                    repos.append(str(data["repo"]))
            except (OSError, ValueError):
                continue
        return repos


# ============================================================================
# GITHUB API CLIENT
# ============================================================================
class GitHubClient:
    def __init__(self, token: str, api_base: str) -> None:
        self.token = token
        self.api_base = api_base.rstrip("/")
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener()
        self._opener.addheaders = [
            ("Accept", "application/vnd.github+json"),
            ("Authorization", f"Bearer {token}"),
            ("User-Agent", CONFIG["user_agent"]),
            ("X-GitHub-Api-Version", "2022-11-28"),
        ]
        self._rate_until = 0.0
        # Rate limit info tracked from response headers.
        self._rl: Dict[str, Any] = {
            "limit": None,
            "remaining": None,
            "reset": None,
            "used": None,
        }

    # ---- rate limit -----------------------------------------------------
    def _track_rate_limit(self, headers: Any) -> None:
        try:
            limit = headers.get("X-RateLimit-Limit")
            remaining = headers.get("X-RateLimit-Remaining")
            reset = headers.get("X-RateLimit-Reset")
            used = headers.get("X-RateLimit-Used")
        except Exception:
            return
        with self._lock:
            if limit is not None:
                try:
                    self._rl["limit"] = int(limit)
                except (TypeError, ValueError):
                    pass
            if remaining is not None:
                try:
                    self._rl["remaining"] = int(remaining)
                except (TypeError, ValueError):
                    pass
            if reset is not None:
                try:
                    self._rl["reset"] = int(reset)
                except (TypeError, ValueError):
                    pass
            if used is not None:
                try:
                    self._rl["used"] = int(used)
                except (TypeError, ValueError):
                    pass

    def rate_limit(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._rl)

    def rate_limit_reset_in(self) -> Optional[float]:
        with self._lock:
            reset = self._rl.get("reset")
        if not reset:
            return None
        return max(0.0, float(reset) - time.time())

    def _wait_for_rate_limit(self) -> None:
        with self._lock:
            remaining = self._rate_until - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)

    # ---- GET ------------------------------------------------------------
    def get(self, path: str) -> Any:
        url = f"{self.api_base}{path}"
        net = CONFIG
        retries = max(0, int(net["retries"]))
        base = max(0.1, float(net["backoff"]))
        cap = max(base, float(net["max_backoff"]))
        timeout = max(1.0, float(net["timeout"]))

        for attempt in range(retries + 1):
            self._wait_for_rate_limit()
            request = urllib.request.Request(url, method="GET")
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    self._track_rate_limit(response.headers)
                    raw = response.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                self._track_rate_limit(exc.headers)
                body = ""
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    pass

                parsed: Dict[str, Any] = {}
                if body:
                    try:
                        loaded = json.loads(body)
                        if isinstance(loaded, dict):
                            parsed = loaded
                    except ValueError:
                        pass

                message = str(parsed.get("message") or f"HTTP {exc.code} {exc.reason}")

                if exc.code == 403:
                    # Could be rate limit or no push access.
                    if "rate limit" in message.lower():
                        reset = exc.headers.get("X-RateLimit-Reset")
                        if reset:
                            try:
                                wait = max(1.0, float(reset) - time.time())
                                with self._lock:
                                    self._rate_until = time.monotonic() + min(wait, cap)
                            except (TypeError, ValueError):
                                pass
                        if attempt < retries:
                            time.sleep(
                                min(cap, base * (2**attempt)) + random.uniform(0, 0.5)
                            )
                            continue
                    raise GitHubError(message, status=403, fatal=True)

                if exc.code == 404:
                    raise GitHubError(message, status=404, fatal=True)

                if exc.code == 401:
                    raise GitHubError(message, status=401, fatal=True)

                retryable = exc.code >= 500 or exc.code in (408, 429, 502, 503, 504)
                if retryable and attempt < retries:
                    time.sleep(min(cap, base * (2**attempt)) + random.uniform(0, 0.5))
                    continue
                raise GitHubError(message, status=exc.code, retryable=retryable)

            except urllib.error.URLError as exc:
                if attempt < retries:
                    time.sleep(min(cap, base * (2**attempt)) + random.uniform(0, 0.5))
                    continue
                raise GitHubError(
                    f"Network error: {exc.reason}", retryable=True
                ) from None
            except json.JSONDecodeError as exc:
                raise GitHubError(f"Invalid JSON from API: {exc}") from None

        raise GitHubError("unreachable")  # pragma: no cover


# ============================================================================
# COLLECTION
# ============================================================================
def fetch_clones(client: GitHubClient, repo: str) -> Dict[str, Any]:
    return client.get(f"/repos/{repo}/traffic/clones") or {}


def fetch_views(client: GitHubClient, repo: str) -> Dict[str, Any]:
    return client.get(f"/repos/{repo}/traffic/views") or {}


def fetch_referrers(client: GitHubClient, repo: str) -> List[Dict[str, Any]]:
    data = client.get(f"/repos/{repo}/traffic/popular/referrers")
    return data if isinstance(data, list) else []


def fetch_paths(client: GitHubClient, repo: str) -> List[Dict[str, Any]]:
    data = client.get(f"/repos/{repo}/traffic/popular/paths")
    return data if isinstance(data, list) else []


def fetch_repo_stats(client: GitHubClient, repo: str) -> RepoStats:
    """Fetch repository metadata (stars, forks, issues, etc.)."""
    data = client.get(f"/repos/{repo}")
    if not isinstance(data, dict):
        return RepoStats()
    license_info = data.get("license") or {}
    return RepoStats(
        fetched=True,
        stars=int(data.get("stargazers_count", 0) or 0),
        forks=int(data.get("forks_count", 0) or 0),
        watchers=int(data.get("watchers_count", 0) or 0),
        subscribers=int(data.get("subscribers_count", 0) or 0),
        open_issues=int(data.get("open_issues_count", 0) or 0),
        size_kb=int(data.get("size", 0) or 0),
        language=data.get("language"),
        license=license_info.get("spdx_id") if isinstance(license_info, dict) else None,
        archived=bool(data.get("archived")),
        disabled=bool(data.get("disabled")),
        is_fork=bool(data.get("fork")),
        default_branch=data.get("default_branch"),
        created_at=data.get("created_at"),
        updated_at=data.get("updated_at"),
        pushed_at=data.get("pushed_at"),
    )


def fetch_release_stats(
    client: GitHubClient, repo: str
) -> Tuple[int, int, Optional[str], int, Optional[str]]:
    """Return (release_count, total_downloads, latest_tag, latest_downloads, latest_at)."""
    try:
        data = client.get(f"/repos/{repo}/releases?per_page=100")
    except GitHubError as exc:
        # 404 for a repo with no releases (some private repos), or 403 on
        # metadata-only tokens. Don't kill the whole collection for this.
        if exc.status in (403, 404):
            return 0, 0, None, 0, None
        raise
    if not isinstance(data, list):
        return 0, 0, None, 0, None

    total = 0
    latest_tag: Optional[str] = None
    latest_dl = 0
    latest_at: Optional[str] = None
    for i, rel in enumerate(data):
        if not isinstance(rel, dict):
            continue
        dl = 0
        for asset in rel.get("assets") or []:
            if isinstance(asset, dict):
                try:
                    dl += int(asset.get("download_count", 0) or 0)
                except (TypeError, ValueError):
                    pass
        total += dl
        if i == 0:
            latest_tag = rel.get("tag_name") or rel.get("name")
            latest_dl = dl
            latest_at = rel.get("published_at") or rel.get("created_at")
    return len(data), total, latest_tag, latest_dl, latest_at


def discover_user_repos(
    client: GitHubClient,
    owner: str,
    include_forks: bool = False,
    include_archived: bool = False,
) -> List[str]:
    """Discover all repos owned by a user/org via the GitHub API."""
    repos: List[str] = []
    page = 1
    while True:
        path = f"/users/{owner}/repos?per_page=100&page={page}&type=owner&sort=updated"
        data = client.get(path)
        if not isinstance(data, list) or not data:
            break
        for entry in data:
            if not isinstance(entry, dict):
                continue
            if entry.get("fork") and not include_forks:
                continue
            if entry.get("archived") and not include_archived:
                continue
            full = entry.get("full_name")
            if isinstance(full, str) and "/" in full:
                repos.append(full)
        if len(data) < 100:
            break
        page += 1
    return repos


def parse_daily(raw: Any) -> List[DailyPoint]:
    if not isinstance(raw, list):
        return []
    out: List[DailyPoint] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        ts = str(entry.get("timestamp", ""))
        date = ts[:10] if len(ts) >= 10 else ""
        try:
            count = int(entry.get("count", 0))
        except (TypeError, ValueError):
            count = 0
        try:
            uniques = int(entry.get("uniques", 0))
        except (TypeError, ValueError):
            uniques = 0
        if date:
            out.append(DailyPoint(date=date, count=count, uniques=uniques))
    out.sort(key=lambda p: p.date)
    return out


def parse_referrers(raw: Any) -> List[Referrer]:
    if not isinstance(raw, list):
        return []
    out: List[Referrer] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        out.append(
            Referrer(
                referrer=str(entry.get("referrer", "")),
                count=int(entry.get("count", 0) or 0),
                uniques=int(entry.get("uniques", 0) or 0),
            )
        )
    out.sort(key=lambda r: r.count, reverse=True)
    return out


def parse_paths(raw: Any) -> List[PopularPath]:
    if not isinstance(raw, list):
        return []
    out: List[PopularPath] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        out.append(
            PopularPath(
                path=str(entry.get("path", "")),
                title=str(entry.get("title", "")),
                count=int(entry.get("count", 0) or 0),
                uniques=int(entry.get("uniques", 0) or 0),
            )
        )
    out.sort(key=lambda p: p.count, reverse=True)
    return out


def collect_repo(
    client: GitHubClient,
    repo: str,
    fetch_stats: bool = True,
) -> TrafficSnapshot:
    fetched_at = _iso_now()
    clones_data = fetch_clones(client, repo)
    views_data = fetch_views(client, repo)
    referrers_raw = fetch_referrers(client, repo)
    paths_raw = fetch_paths(client, repo)

    stats = RepoStats()
    if fetch_stats:
        stats = fetch_repo_stats(client, repo)
        (
            stats.release_count,
            stats.release_downloads,
            stats.latest_release_tag,
            stats.latest_release_downloads,
            stats.latest_release_at,
        ) = fetch_release_stats(client, repo)

    return TrafficSnapshot(
        repo=repo,
        fetched_at=fetched_at,
        clones_total=int(clones_data.get("count", 0) or 0),
        clones_uniques=int(clones_data.get("uniques", 0) or 0),
        clones_daily=parse_daily(clones_data.get("clones")),
        views_total=int(views_data.get("count", 0) or 0),
        views_uniques=int(views_data.get("uniques", 0) or 0),
        views_daily=parse_daily(views_data.get("views")),
        referrers=parse_referrers(referrers_raw),
        paths=parse_paths(paths_raw),
        stats=stats,
    )


# ============================================================================
# ANALYSIS / SUMMARY
# ============================================================================
def _mean_std(values: Sequence[float]) -> Tuple[float, float]:
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return mean, var**0.5


def detect_spikes(
    daily: Sequence[DailyPoint],
    threshold: float = 2.0,
    min_abs: int = 5,
) -> List[Tuple[str, int, float]]:
    """Return (date, count, z_score) for days with z >= threshold."""
    if len(daily) < 3:
        return []
    counts = [p.count for p in daily]
    mean, std = _mean_std(counts)
    if std <= 0 or mean <= 0:
        return []
    out: List[Tuple[str, int, float]] = []
    for p in daily:
        z = (p.count - mean) / std
        if z >= threshold and p.count >= min_abs:
            out.append((p.date, p.count, round(z, 2)))
    return out


def build_analysis(snap: TrafficSnapshot) -> Analysis:
    analysis = Analysis()

    if snap.views_total > 0:
        analysis.clone_view_ratio = round(snap.clones_total / snap.views_total, 2)

    threshold = float(CONFIG.get("spike_z_threshold", 2.0))
    analysis.clone_spikes = detect_spikes(snap.clones_daily, threshold=threshold)
    analysis.view_spikes = detect_spikes(snap.views_daily, threshold=threshold)

    if snap.clones_daily:
        analysis.peak_clone_day = max(snap.clones_daily, key=lambda p: p.count)
    if snap.views_daily:
        analysis.peak_view_day = max(snap.views_daily, key=lambda p: p.count)

    # Heuristic: lots of clones, almost no human visitors => likely bot/CI.
    ratio_threshold = int(CONFIG.get("bot_ratio_threshold", 100))
    unique_floor = int(CONFIG.get("bot_unique_view_floor", 5))
    if snap.views_uniques <= unique_floor and snap.clones_uniques >= ratio_threshold:
        analysis.likely_bot_traffic = True
        analysis.notes.append(
            f"High clones ({snap.clones_total}) with only "
            f"{snap.views_uniques} unique visitor(s) suggests automated "
            f"traffic (CI, scripts, templates, or crawlers)."
        )

    if snap.clones_total + snap.views_total < 30:
        analysis.low_traffic = True
        analysis.notes.append("Very low traffic in the last 14 days.")

    return analysis


def build_summary(snap: TrafficSnapshot, cached: bool = False) -> RepoSummary:
    return RepoSummary(
        repo=snap.repo,
        clones_total=snap.clones_total,
        clones_uniques=snap.clones_uniques,
        views_total=snap.views_total,
        views_uniques=snap.views_uniques,
        referrer_count=len(snap.referrers),
        path_count=len(snap.paths),
        stars=snap.stats.stars,
        forks=snap.stats.forks,
        open_issues=snap.stats.open_issues,
        downloads=snap.stats.release_downloads,
        cached=cached,
    )


def repo_list_from_file(path: str) -> List[str]:
    repos: List[str] = []
    with open(path, "r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            for token in re.split(r"[\s,;]+", line):
                if "/" in token:
                    repos.append(token)
    return repos


def normalize_repo(value: str) -> Optional[str]:
    value = value.strip().strip("/")
    if value.count("/") != 1:
        return None
    owner, name = value.split("/", 1)
    if not owner or not name:
        return None
    return f"{owner}/{name}"


# ============================================================================
# RENDER: HUMAN
# ============================================================================
WIDTH = 80


def _fmt_dt(value: Optional[str]) -> str:
    if not value:
        return "-"
    return str(value)[:10]


def render_repo(snap: TrafficSnapshot, redact: bool, cached: bool = False) -> None:
    divider = paint("=" * WIDTH, C.GREY)
    print(divider)
    header = f"{paint('REPOSITORY', C.BOLD)}  {snap.repo}"
    if cached:
        header += paint("  [cached]", C.YELLOW)
    print(header)
    print(f"{paint('FETCHED', C.BOLD)}      {snap.fetched_at}")
    print(divider)
    print()

    # ---- Repo metadata ---------------------------------------------------
    if snap.stats.fetched:
        s = snap.stats
        print(paint("REPOSITORY INFO", C.BOLD))
        print(
            f"  Stars: {paint(str(s.stars), C.GREEN)}   "
            f"Forks: {paint(str(s.forks), C.CYAN)}   "
            f"Watchers: {s.watchers}   "
            f"Subscribers: {s.subscribers}   "
            f"Open issues: {s.open_issues}"
        )
        extras = []
        if s.language:
            extras.append(f"Language: {s.language}")
        if s.license and s.license != "NOASSERTION":
            extras.append(f"License: {s.license}")
        extras.append(f"Size: {s.size_kb} KB")
        if s.archived:
            extras.append(paint("ARCHIVED", C.YELLOW))
        if s.disabled:
            extras.append(paint("DISABLED", C.RED))
        if s.is_fork:
            extras.append("Fork")
        print("  " + "   ".join(extras))
        print(
            f"  Created: {_fmt_dt(s.created_at)}   "
            f"Updated: {_fmt_dt(s.updated_at)}   "
            f"Pushed: {_fmt_dt(s.pushed_at)}"
        )
        if s.release_count or s.latest_release_tag:
            latest = s.latest_release_tag or "?"
            print(
                f"  Releases: {s.release_count}   "
                f"Total downloads: {paint(str(s.release_downloads), C.GREEN)}   "
                f"Latest: {latest} ({s.latest_release_downloads} downloads)"
            )
        print()

    # ---- Clones ----------------------------------------------------------
    print(paint("CLONES (last 14 days)", C.BOLD))
    print(
        f"  Total: {paint(str(snap.clones_total), C.GREEN)}   "
        f"Unique cloners: {paint(str(snap.clones_uniques), C.CYAN)}"
    )
    if snap.clones_daily:
        print()
        print(f"  {'DATE':<12}  {'COUNT':>6}  {'UNIQUE':>6}")
        for p in snap.clones_daily:
            print(f"  {p.date:<12}  {p.count:>6}  {p.uniques:>6}")
    print()

    # ---- Views -----------------------------------------------------------
    print(paint("VIEWS (last 14 days)", C.BOLD))
    print(
        f"  Total: {paint(str(snap.views_total), C.GREEN)}   "
        f"Unique visitors: {paint(str(snap.views_uniques), C.CYAN)}"
    )
    if snap.views_daily:
        print()
        print(f"  {'DATE':<12}  {'COUNT':>6}  {'UNIQUE':>6}")
        for p in snap.views_daily:
            print(f"  {p.date:<12}  {p.count:>6}  {p.uniques:>6}")
    print()

    # ---- Referrers -------------------------------------------------------
    print(paint(f"REFERRING SITES ({len(snap.referrers)})", C.BOLD))
    if not snap.referrers:
        print("  (none)")
    else:
        width = max(20, max(len(r.referrer) for r in snap.referrers))
        print(f"  {'SITE'.ljust(width)}  {'VIEWS':>6}  {'UNIQUE':>6}")
        for r in snap.referrers:
            print(f"  {r.referrer.ljust(width)}  {r.count:>6}  {r.uniques:>6}")
    print()

    # ---- Paths -----------------------------------------------------------
    print(paint(f"POPULAR CONTENT ({len(snap.paths)})", C.BOLD))
    if not snap.paths:
        print("  (none)")
    else:
        width = max(40, min(70, max(len(p.path) for p in snap.paths)))
        print(f"  {'CONTENT'.ljust(width)}  {'VIEWS':>6}  {'UNIQUE':>6}")
        for p in snap.paths:
            path = p.path
            if len(path) > width:
                path = path[: width - 1] + "\u2026"
            print(f"  {path.ljust(width)}  {p.count:>6}  {p.uniques:>6}")
    print()

    # ---- Analysis --------------------------------------------------------
    analysis = build_analysis(snap)
    print(paint("ACTIVITY ANALYSIS", C.BOLD))
    print(f"  Clone/view ratio: {analysis.clone_view_ratio}")
    if analysis.peak_clone_day:
        pc = analysis.peak_clone_day
        print(
            f"  Peak clone day:   {pc.date} ({pc.count} clones, {pc.uniques} uniques)"
        )
    if analysis.peak_view_day:
        pv = analysis.peak_view_day
        print(f"  Peak view day:    {pv.date} ({pv.count} views, {pv.uniques} uniques)")
    if analysis.clone_spikes:
        print("  Clone spikes:")
        for date, count, z in analysis.clone_spikes:
            print(f"    {date}  {count:>6}  (z={z})")
    if analysis.view_spikes:
        print("  View spikes:")
        for date, count, z in analysis.view_spikes:
            print(f"    {date}  {count:>6}  (z={z})")
    for note in analysis.notes:
        print(f"  {paint('!', C.YELLOW)} {note}")
    print()


def render_summary(summaries: Sequence[RepoSummary]) -> None:
    if not summaries:
        return
    print()
    print(paint("SUMMARY", C.BOLD))
    print(paint("=" * 120, C.GREY))
    repo_width = max(len(s.repo) for s in summaries) + 2
    header = (
        "REPOSITORY".ljust(repo_width)
        + "CLONES".rjust(9)
        + "UNIQUE".rjust(9)
        + "VIEWS".rjust(9)
        + "UNIQUE".rjust(9)
        + "RATIO".rjust(8)
        + "STARS".rjust(8)
        + "FORKS".rjust(8)
        + "ISSUES".rjust(8)
        + "DL".rjust(10)
        + "REF".rjust(6)
        + "PATH".rjust(6)
    )
    print(paint(header, C.BOLD))
    print(paint("-" * 120, C.GREY))
    for s in summaries:
        if s.error:
            print(
                s.repo.ljust(repo_width)
                + paint("ERROR".ljust(9), C.RED)
                + " " * 68
                + paint(s.error[:40], C.GREY)
            )
            continue
        ratio = ""
        if s.views_total > 0:
            ratio = f"{s.clones_total / s.views_total:.2f}"
        cached_marker = paint("*", C.YELLOW) if s.cached else ""
        print(
            s.repo.ljust(repo_width)
            + str(s.clones_total).rjust(9)
            + str(s.clones_uniques).rjust(9)
            + str(s.views_total).rjust(9)
            + str(s.views_uniques).rjust(9)
            + ratio.rjust(8)
            + str(s.stars).rjust(8)
            + str(s.forks).rjust(8)
            + str(s.open_issues).rjust(8)
            + str(s.downloads).rjust(10)
            + str(s.referrer_count).rjust(6)
            + str(s.path_count).rjust(6)
            + cached_marker
        )
    print()
    if any(s.cached for s in summaries):
        print(paint("  * = served from cache", C.GREY))


def render_history(archive: Archive, repo: str) -> None:
    data = archive.load(repo)
    if not data:
        warn(f"No archived data for {repo}.", C.YELLOW)
        return

    print(paint("=" * WIDTH, C.GREY))
    print(f"{paint('ARCHIVED HISTORY', C.BOLD)}  {repo}")
    print(f"{paint('UPDATED', C.BOLD)}          {data.get('updated', '?')}")
    print(paint("=" * WIDTH, C.GREY))
    print()

    clones = data.get("clones") or {}
    views = data.get("views") or {}
    if clones or views:
        print(paint("DAILY HISTORY", C.BOLD))
        dates = sorted(set(clones) | set(views))
        print(
            f"  {'DATE':<12}  {'CLONES':>6}  {'CL-UNIQ':>7}  {'VIEWS':>6}  {'VW-UNIQ':>7}"
        )
        for d in dates:
            c = clones.get(d, {})
            v = views.get(d, {})
            print(
                f"  {d:<12}  {str(c.get('count', '')):>6}  "
                f"{str(c.get('uniques', '')):>7}  "
                f"{str(v.get('count', '')):>6}  "
                f"{str(v.get('uniques', '')):>7}"
            )
        print()

    stats_history = data.get("stats_history") or []
    if stats_history:
        print(paint("METADATA HISTORY", C.BOLD))
        print(
            f"  {'DATE':<12}  {'STARS':>6}  {'FORKS':>6}  "
            f"{'WATCH':>6}  {'ISSUES':>7}  {'DOWNLOADS':>10}"
        )
        for entry in stats_history:
            print(
                f"  {str(entry.get('date', '')):<12}  "
                f"{str(entry.get('stars', '')):>6}  "
                f"{str(entry.get('forks', '')):>6}  "
                f"{str(entry.get('watchers', '')):>6}  "
                f"{str(entry.get('open_issues', '')):>7}  "
                f"{str(entry.get('release_downloads', '')):>10}"
            )
        print()

    ref_snaps = data.get("referrer_snapshots") or []
    if ref_snaps:
        latest = ref_snaps[-1]
        print(paint(f"LATEST REFERRERS (snapshot {latest.get('date', '?')})", C.BOLD))
        for r in latest.get("data", [])[:10]:
            print(
                f"  {r.get('referrer', '?'):<30}  {r.get('count', 0):>6}  {r.get('uniques', 0):>6}"
            )
        print()

    path_snaps = data.get("path_snapshots") or []
    if path_snaps:
        latest = path_snaps[-1]
        print(
            paint(
                f"LATEST POPULAR CONTENT (snapshot {latest.get('date', '?')})", C.BOLD
            )
        )
        for p in latest.get("data", [])[:10]:
            print(f"  {p.get('path', '?'):<50}  {p.get('count', 0):>6}")
        print()


# ============================================================================
# RENDER: JSON / CSV
# ============================================================================
def snapshot_to_dict(snap: TrafficSnapshot, redact: bool) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "repo": snap.repo,
        "fetched_at": snap.fetched_at,
        "clones": {
            "total": snap.clones_total,
            "uniques": snap.clones_uniques,
            "daily": [
                {"date": p.date, "count": p.count, "uniques": p.uniques}
                for p in snap.clones_daily
            ],
        },
        "views": {
            "total": snap.views_total,
            "uniques": snap.views_uniques,
            "daily": [
                {"date": p.date, "count": p.count, "uniques": p.uniques}
                for p in snap.views_daily
            ],
        },
        "referrers": [
            {"referrer": r.referrer, "count": r.count, "uniques": r.uniques}
            for r in snap.referrers
        ],
        "paths": [
            {"path": p.path, "title": p.title, "count": p.count, "uniques": p.uniques}
            for p in snap.paths
        ],
        "stats": snap.stats.to_dict(),
    }
    if redact:
        d = redact_snapshot(d)
    return d


def redact_snapshot(data: Any) -> Any:
    """Redact repo names and paths, but keep numeric data intact."""
    if isinstance(data, dict):
        out: Dict[str, Any] = {}
        for k, v in data.items():
            if k in ("repo",):
                out[k] = "[REDACTED]"
            elif k == "title" and isinstance(v, str):
                out[k] = "[REDACTED]"
            elif k == "path" and isinstance(v, str):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_snapshot(v)
        return out
    if isinstance(data, list):
        return [redact_snapshot(v) for v in data]
    return data


def write_csv_summary(path: str, summaries: Sequence[RepoSummary]) -> None:
    fields = [
        "repo",
        "clones_total",
        "clones_uniques",
        "views_total",
        "views_uniques",
        "clone_view_ratio",
        "stars",
        "forks",
        "open_issues",
        "release_downloads",
        "referrers",
        "paths",
        "cached",
    ]
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for s in summaries:
            ratio = ""
            if s.views_total > 0:
                ratio = round(s.clones_total / s.views_total, 4)
            writer.writerow(
                {
                    "repo": s.repo,
                    "clones_total": s.clones_total,
                    "clones_uniques": s.clones_uniques,
                    "views_total": s.views_total,
                    "views_uniques": s.views_uniques,
                    "clone_view_ratio": ratio,
                    "stars": s.stars,
                    "forks": s.forks,
                    "open_issues": s.open_issues,
                    "release_downloads": s.downloads,
                    "referrers": s.referrer_count,
                    "paths": s.path_count,
                    "cached": int(s.cached),
                }
            )


def write_csv_daily(path: str, snapshots: Sequence[TrafficSnapshot]) -> None:
    fields = ["repo", "type", "date", "count", "uniques"]
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for snap in snapshots:
            for p in snap.clones_daily:
                writer.writerow(
                    {
                        "repo": snap.repo,
                        "type": "clones",
                        "date": p.date,
                        "count": p.count,
                        "uniques": p.uniques,
                    }
                )
            for p in snap.views_daily:
                writer.writerow(
                    {
                        "repo": snap.repo,
                        "type": "views",
                        "date": p.date,
                        "count": p.count,
                        "uniques": p.uniques,
                    }
                )


# ============================================================================
# SELF TEST
# ============================================================================
def run_self_test() -> int:
    print(f"gh-traffic {__version__} self-test")
    failures = 0

    def check(label: str, condition: Any) -> None:
        nonlocal failures
        ok = bool(condition)
        print(f"  {'PASS' if ok else 'FAIL':<4} {label}")
        if not ok:
            failures += 1

    # ---- daily parsing ---------------------------------------------------
    raw = [
        {"timestamp": "2026-09-28T00:00:00Z", "count": 10, "uniques": 5},
        {"timestamp": "2026-09-29T00:00:00Z", "count": 20, "uniques": 8},
    ]
    daily = parse_daily(raw)
    check("parse_daily.count", len(daily) == 2)
    check("parse_daily.date", daily[0].date == "2026-09-28")
    check("parse_daily.count_val", daily[0].count == 10)
    check("parse_daily.uniques", daily[0].uniques == 5)

    # ---- referrers -------------------------------------------------------
    refs = parse_referrers(
        [
            {"referrer": "Google", "count": 10, "uniques": 5},
            {"referrer": "github.com", "count": 3, "uniques": 2},
        ]
    )
    check("parse_referrers.count", len(refs) == 2)
    check("parse_referrers.sorted", refs[0].referrer == "Google")

    # ---- paths -----------------------------------------------------------
    paths = parse_paths(
        [
            {"path": "/a", "title": "A", "count": 100, "uniques": 50},
            {"path": "/b", "title": "B", "count": 50, "uniques": 20},
        ]
    )
    check("parse_paths.count", len(paths) == 2)
    check("parse_paths.sorted", paths[0].path == "/a")

    # ---- repo normalization ---------------------------------------------
    check(
        "repo.normalize.ok",
        normalize_repo("your-username/your-repo-name")
        == "your-username/your-repo-name",
    )
    check("repo.normalize.bad", normalize_repo("not-a-repo") is None)
    check("repo.normalize.slash", normalize_repo("/owner/name/") == "owner/name")

    # ---- repo stats -----------------------------------------------------
    stats = RepoStats(
        fetched=True,
        stars=12,
        forks=3,
        watchers=12,
        subscribers=4,
        open_issues=1,
        size_kb=500,
        language="Python",
        license="MIT",
        release_count=2,
        release_downloads=250,
        latest_release_tag="v1.0.0",
        latest_release_downloads=100,
    )
    sd = stats.to_dict()
    check("stats.to_dict.stars", sd["stars"] == 12)
    check("stats.to_dict.downloads", sd["release_downloads"] == 250)

    # ---- summary ---------------------------------------------------------
    snap = TrafficSnapshot(
        repo="owner/name",
        fetched_at="2026-10-12T00:00:00Z",
        clones_total=100,
        clones_uniques=50,
        clones_daily=[],
        views_total=200,
        views_uniques=10,
        views_daily=[],
        referrers=[Referrer("Google", 5, 5)],
        paths=[PopularPath("/x", "X", 10, 5)],
        stats=stats,
    )
    summary = build_summary(snap)
    check("summary.clones", summary.clones_total == 100)
    check("summary.views", summary.views_total == 200)
    check("summary.refs", summary.referrer_count == 1)
    check("summary.paths", summary.path_count == 1)
    check("summary.stars", summary.stars == 12)
    check("summary.downloads", summary.downloads == 250)

    # ---- spike detection -------------------------------------------------
    spike_daily = [
        DailyPoint("2026-09-27", 5, 3),
        DailyPoint("2026-09-28", 6, 3),
        DailyPoint("2026-09-29", 4, 2),
        DailyPoint("2026-09-30", 5, 2),
        DailyPoint("2026-10-01", 200, 100),  # spike
        DailyPoint("2026-10-02", 5, 2),
    ]
    spikes = detect_spikes(spike_daily, threshold=2.0, min_abs=5)
    check("spike.detected", len(spikes) == 1)
    check("spike.date", spikes and spikes[0][0] == "2026-10-01")
    check("spike.count", spikes and spikes[0][1] == 200)

    # ---- analysis --------------------------------------------------------
    analysis = build_analysis(snap)
    check("analysis.ratio", analysis.clone_view_ratio == 0.5)
    check("analysis.peak_clone_none", analysis.peak_clone_day is None)

    bot_snap = TrafficSnapshot(
        repo="owner/bot",
        fetched_at="2026-10-12T00:00:00Z",
        clones_total=500,
        clones_uniques=200,
        clones_daily=[],
        views_total=50,
        views_uniques=2,
        views_daily=[],
        referrers=[],
        paths=[],
        stats=RepoStats(),
    )
    bot_analysis = build_analysis(bot_snap)
    check("analysis.bot_flag", bot_analysis.likely_bot_traffic is True)
    check("analysis.bot_note", len(bot_analysis.notes) >= 1)

    low_snap = TrafficSnapshot(
        repo="owner/low",
        fetched_at="2026-10-12T00:00:00Z",
        clones_total=3,
        clones_uniques=2,
        clones_daily=[],
        views_total=5,
        views_uniques=1,
        views_daily=[],
        referrers=[],
        paths=[],
        stats=RepoStats(),
    )
    low_analysis = build_analysis(low_snap)
    check("analysis.low_traffic", low_analysis.low_traffic is True)

    # ---- redaction -------------------------------------------------------
    redacted = redact_snapshot({"repo": "owner/name", "path": "/secret", "count": 5})
    check("redact.repo", redacted["repo"] == "[REDACTED]")
    check("redact.path", redacted["path"] == "[REDACTED]")
    check("redact.count_preserved", redacted["count"] == 5)

    # ---- archive merge ---------------------------------------------------
    arch = Archive(Path(tempfile.mkdtemp(prefix="gh-traffic-test-")), enabled=True)
    try:
        s1 = TrafficSnapshot(
            repo="owner/name",
            fetched_at="2026-10-01T00:00:00Z",
            clones_total=10,
            clones_uniques=5,
            clones_daily=[DailyPoint("2026-09-28", 10, 5)],
            views_total=50,
            views_uniques=3,
            views_daily=[DailyPoint("2026-09-28", 50, 3)],
            referrers=[Referrer("Google", 2, 2)],
            paths=[PopularPath("/a", "A", 5, 3)],
            stats=stats,
        )
        merged = arch.merge(s1)
        check("archive.merge_clones", merged["clones"]["2026-09-28"]["count"] == 10)
        check("archive.merge_views", merged["views"]["2026-09-28"]["count"] == 50)
        check("archive.merge_refs", len(merged["referrer_snapshots"]) == 1)
        check("archive.last_snapshot", isinstance(merged.get("last_snapshot"), dict))
        check("archive.stats_history", len(merged.get("stats_history") or []) == 1)

        s2 = TrafficSnapshot(
            repo="owner/name",
            fetched_at="2026-10-02T00:00:00Z",
            clones_total=15,
            clones_uniques=7,
            clones_daily=[DailyPoint("2026-09-29", 15, 7)],
            views_total=60,
            views_uniques=4,
            views_daily=[DailyPoint("2026-09-29", 60, 4)],
            referrers=[Referrer("Google", 3, 3)],
            paths=[PopularPath("/b", "B", 7, 4)],
            stats=stats,
        )
        # Merge into the same repo - the Archive reads from disk, so we
        # need to save the first result first.
        arch.save("owner/name", merged)
        merged2 = arch.merge(s2)
        check("archive.merge_two_days", len(merged2["clones"]) == 2)
        check("archive.merge_refs_two", len(merged2["referrer_snapshots"]) == 2)

        # round-trip snapshot reconstruction
        arch.save("owner/name", merged2)
        restored = arch.load_snapshot("owner/name")
        check("archive.restore_snapshot", restored is not None)
        check("archive.restore_clones", restored and restored.clones_total == 15)
        check("archive.restore_stats", restored and restored.stats.stars == 12)

        # cache freshness check
        arch.save("owner/name", merged2)
        check("archive.is_fresh_true", arch.is_fresh("owner/name", 10**12))
        check("archive.is_fresh_false", not arch.is_fresh("owner/name", 1))
    finally:
        shutil.rmtree(arch.root, ignore_errors=True)

    # ---- file parsing ----------------------------------------------------
    # (not testing actual file I/O here to keep the self-test hermetic)
    check("repos.parse_inline", normalize_repo("a/b") == "a/b")

    print()
    print(f"Result: {'PASS' if failures == 0 else f'{failures} failure(s)'}")
    return 0 if failures == 0 else 1


# ============================================================================
# ARGPARSE
# ============================================================================
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="gh-traffic.py",
        description=(
            "Pull GitHub repository traffic statistics (clones, views, "
            "referrers, popular paths, metadata, releases) for one or "
            "more repositories."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python gh-traffic.py --repo your-username/your-repo-name\n"
            "  python gh-traffic.py --file repos.txt\n"
            "  python gh-traffic.py --file repos.txt --json\n"
            "  python gh-traffic.py --file repos.txt --csv traffic.csv\n"
            "  python gh-traffic.py --repo your-username/your-repo-name --archive ~/.gh-traffic\n"
            "  python gh-traffic.py --repo your-username/your-repo-name --history\n"
            "  python gh-traffic.py --discover your-username --include-forks\n"
            "  python gh-traffic.py --repo your-username/your-repo-name --cache-ttl 3600\n"
            "  python gh-traffic.py --repo your-username/your-repo-name --refresh\n"
            "  python gh-traffic.py --self-test\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"gh-traffic.py {__version__}",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline tests and exit.",
    )
    parser.add_argument(
        "--token",
        help="GitHub token. Prefer the GITHUB_TOKEN environment variable.",
    )

    src = parser.add_argument_group("repositories")
    src.add_argument(
        "--repo",
        action="append",
        default=[],
        metavar="OWNER/NAME",
        help="Repository to check. Repeatable.",
    )
    src.add_argument(
        "--file",
        "-f",
        help="Read repository list from a file (one per line, # comments).",
    )
    src.add_argument(
        "--discover",
        metavar="OWNER",
        help="Auto-discover repos owned by a user/org via the GitHub API.",
    )
    src.add_argument(
        "--include-forks",
        action="store_true",
        help="Include forked repos when using --discover.",
    )
    src.add_argument(
        "--include-archived",
        action="store_true",
        help="Include archived repos when using --discover.",
    )
    src.add_argument(
        "--list-repos",
        action="store_true",
        help="List repositories in the archive and exit.",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "--json",
        action="store_true",
        help="Print a single JSON document to stdout.",
    )
    out.add_argument(
        "--jsonl",
        action="store_true",
        help="Print one JSON object per repository.",
    )
    out.add_argument(
        "--csv",
        metavar="PATH",
        help="Write a summary CSV (one row per repository).",
    )
    out.add_argument(
        "--csv-daily",
        metavar="PATH",
        help="Write a daily clones/views CSV.",
    )
    out.add_argument(
        "--history",
        action="store_true",
        help="Show archived history instead of fetching from the API.",
    )
    out.add_argument(
        "--redact",
        action="store_true",
        help="Redact repo names and paths in the output.",
    )
    out.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors.",
    )
    out.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational notes.",
    )
    out.add_argument(
        "--no-repo-stats",
        action="store_true",
        help="Skip fetching repo metadata (stars/forks/issues/releases).",
    )

    arch = parser.add_argument_group("archive & cache")
    arch.add_argument(
        "--archive",
        metavar="DIR",
        help="Archive directory (default: ~/.cache/gh-traffic).",
    )
    arch.add_argument(
        "--no-archive",
        action="store_true",
        help="Do not read or write the archive.",
    )
    arch.add_argument(
        "--cache-ttl",
        type=float,
        metavar="SECONDS",
        help="Reuse cached data if younger than this many seconds (0 = disabled).",
    )
    arch.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore the cache and always fetch fresh data.",
    )

    net = parser.add_argument_group("network")
    net.add_argument(
        "--workers",
        type=int,
        help="Parallel lookups (default: 4).",
    )
    net.add_argument(
        "--timeout",
        type=float,
        help="Per-request timeout in seconds (default: 30).",
    )
    net.add_argument(
        "--retries",
        type=int,
        help="Extra retries on transient failures (default: 3).",
    )

    return parser.parse_args(argv)


# ============================================================================
# MAIN
# ============================================================================
def resolve_token(args: argparse.Namespace) -> Optional[str]:
    if args.token:
        return args.token.strip() or None
    for env in ("GITHUB_TOKEN", "GH_TOKEN", "GITHUB_ACCESS_TOKEN"):
        value = os.environ.get(env)
        if value:
            return value.strip() or None
    return None


def format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def main(argv: Optional[Sequence[str]] = None) -> int:
    global USE_COLOR

    args = parse_args(argv)

    if args.self_test:
        return run_self_test()

    USE_COLOR = (
        not args.no_color
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
        and not args.json
        and not args.jsonl
    )

    # ---- config overrides ------------------------------------------------
    if args.no_repo_stats:
        CONFIG["repo_stats"] = False
    if args.cache_ttl is not None:
        CONFIG["cache_ttl"] = max(0.0, float(args.cache_ttl))

    # ---- archive setup ---------------------------------------------------
    if args.archive:
        archive_dir = Path(args.archive).expanduser()
    elif CONFIG.get("archive_dir"):
        archive_dir = Path(CONFIG["archive_dir"]).expanduser()
    else:
        archive_dir = default_archive_dir()

    archive = Archive(archive_dir, enabled=not args.no_archive)

    # ---- list repos shortcut --------------------------------------------
    if args.list_repos:
        repos = archive.list_repos()
        if not repos:
            warn("No repositories in the archive.", C.YELLOW)
            return 1
        for repo in repos:
            print(repo)
        return 0

    # ---- token -----------------------------------------------------------
    token = resolve_token(args)
    if not token:
        warn(
            "ERROR: no GitHub token. Set GITHUB_TOKEN, or pass --token.",
            C.RED,
        )
        warn(
            "       The traffic endpoints require push (write) access to each repo.",
            C.GREY,
        )
        return 2

    # ---- network overrides -----------------------------------------------
    if args.workers is not None:
        CONFIG["workers"] = max(1, args.workers)
    if args.timeout is not None:
        CONFIG["timeout"] = max(1.0, args.timeout)
    if args.retries is not None:
        CONFIG["retries"] = max(0, args.retries)

    client = GitHubClient(token, CONFIG["api_base"])

    # ---- collect repo list ----------------------------------------------
    repos: List[str] = []
    for raw in args.repo:
        normalized = normalize_repo(raw)
        if normalized:
            repos.append(normalized)
        else:
            warn(f"Skipping invalid repo: {raw!r}", C.YELLOW)

    if args.file:
        try:
            repos.extend(repo_list_from_file(args.file))
        except OSError as exc:
            warn(f"ERROR: cannot read {args.file}: {exc}", C.RED)
            return 2

    if args.discover:
        if not args.quiet:
            warn(f"Discovering repositories for {args.discover}...", C.GREY)
        try:
            discovered = discover_user_repos(
                client,
                args.discover,
                include_forks=args.include_forks,
                include_archived=args.include_archived,
            )
        except GitHubError as exc:
            warn(f"ERROR: discovery failed: {exc}", C.RED)
            return 2
        if not args.quiet:
            warn(f"  Found {len(discovered)} repo(s).", C.GREY)
        repos.extend(discovered)

    if not repos and CONFIG.get("repos"):
        repos.extend(CONFIG["repos"])

    if not repos:
        warn(
            "No repositories given. Use --repo OWNER/NAME, --file FILE, "
            "--discover OWNER, or set CONFIG['repos'].",
            C.RED,
        )
        return 1

    # Deduplicate while preserving order.
    seen = set()
    repos = [r for r in repos if not (r in seen or seen.add(r))]

    # ---- history mode ----------------------------------------------------
    if args.history:
        for repo in repos:
            render_history(archive, repo)
        return 0

    # ---- fetch -----------------------------------------------------------
    snapshots: List[TrafficSnapshot] = []
    summaries: List[RepoSummary] = []
    errors = 0
    cache_hits = 0
    cache_ttl = float(CONFIG.get("cache_ttl", 0))
    fetch_stats = bool(CONFIG.get("repo_stats", True))

    if not args.quiet:
        warn(
            f"Fetching traffic for {len(repos)} repo(s) "
            f"with {CONFIG['workers']} worker(s)"
            + (f" [cache TTL: {cache_ttl:.0f}s]" if cache_ttl > 0 else "")
            + (" [refresh]" if args.refresh else "")
            + "...",
            C.GREY,
        )

    def fetch_one(
        repo: str,
    ) -> Tuple[str, Optional[TrafficSnapshot], Optional[str], bool]:
        # Cache check first
        if not args.refresh and cache_ttl > 0 and archive.enabled:
            if archive.is_fresh(repo, cache_ttl):
                cached = archive.load_snapshot(repo)
                if cached is not None:
                    return repo, cached, None, True
        try:
            snap = collect_repo(client, repo, fetch_stats=fetch_stats)
            return repo, snap, None, False
        except GitHubError as exc:
            if exc.status == 403:
                return (
                    repo,
                    None,
                    "403 Forbidden: token lacks push access to this repo.",
                    False,
                )
            if exc.status == 404:
                return repo, None, "404 Not Found: repo does not exist.", False
            return repo, None, str(exc), False
        except Exception as exc:
            return repo, None, f"Unexpected error: {type(exc).__name__}: {exc}", False

    workers = max(1, int(CONFIG["workers"]))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_one, r): r for r in repos}
        for future in concurrent.futures.as_completed(futures):
            repo, snap, error, from_cache = future.result()
            if error:
                errors += 1
                summaries.append(RepoSummary(repo=repo, error=error))
                if not args.quiet:
                    warn(f"  [!] {repo}: {error}", C.RED)
                continue

            assert snap is not None
            if from_cache:
                cache_hits += 1
            snapshots.append(snap)
            summaries.append(build_summary(snap, cached=from_cache))

    order = {r: i for i, r in enumerate(repos)}
    snapshots.sort(key=lambda s: order.get(s.repo, 999))
    summaries.sort(key=lambda s: order.get(s.repo, 999))

    # ---- archive write ---------------------------------------------------
    if archive.enabled:
        for snap in snapshots:
            cached = any(s.repo == snap.repo and s.cached for s in summaries)
            if cached:
                continue
            try:
                merged = archive.merge(snap)
                archive.save(snap.repo, merged)
            except Exception as exc:
                warn(f"Archive error for {snap.repo}: {exc}", C.YELLOW)

    # ---- output ----------------------------------------------------------
    if args.json:
        payload = {
            "generated_at": _iso_now(),
            "repositories": [
                snapshot_to_dict(s, redact=args.redact) for s in snapshots
            ],
            "errors": [
                {"repo": s.repo, "error": s.error} for s in summaries if s.error
            ],
            "rate_limit": client.rate_limit(),
            "cache_hits": cache_hits,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.jsonl:
        for s in snapshots:
            print(
                json.dumps(snapshot_to_dict(s, redact=args.redact), ensure_ascii=False)
            )
        for s in summaries:
            if s.error:
                print(
                    json.dumps({"repo": s.repo, "error": s.error}, ensure_ascii=False)
                )
    else:
        for snap in snapshots:
            cached = any(s.repo == snap.repo and s.cached for s in summaries)
            render_repo(snap, redact=args.redact, cached=cached)
        if len(snapshots) > 1 or errors:
            render_summary(summaries)

    # ---- CSV outputs -----------------------------------------------------
    if args.csv:
        if not summaries:
            warn("Nothing to write to CSV.", C.YELLOW)
        else:
            try:
                write_csv_summary(args.csv, summaries)
                if not args.quiet:
                    warn(f"Summary CSV written to: {args.csv}", C.GREEN)
            except OSError as exc:
                warn(f"ERROR: cannot write {args.csv}: {exc}", C.RED)
                return 2

    if args.csv_daily:
        if not snapshots:
            warn("Nothing to write to daily CSV.", C.YELLOW)
        else:
            try:
                write_csv_daily(args.csv_daily, snapshots)
                if not args.quiet:
                    warn(f"Daily CSV written to: {args.csv_daily}", C.GREEN)
            except OSError as exc:
                warn(f"ERROR: cannot write {args.csv_daily}: {exc}", C.RED)
                return 2

    # ---- footer ----------------------------------------------------------
    if not args.quiet:
        ok = len(snapshots)
        total_clones = sum(s.clones_total for s in snapshots)
        total_views = sum(s.views_total for s in snapshots)
        total_dl = sum(s.stats.release_downloads for s in snapshots)
        warn(
            f"{len(repos)} repo(s) | {ok} succeeded, {errors} failed | "
            f"cache hits: {cache_hits} | "
            f"total clones: {total_clones:,} | "
            f"total views: {total_views:,} | "
            f"total downloads: {total_dl:,}",
            C.GREY,
        )
        rl = client.rate_limit()
        if rl.get("remaining") is not None and rl.get("limit") is not None:
            reset_in = client.rate_limit_reset_in()
            suffix = (
                f" (resets in {format_duration(reset_in)})"
                if reset_in is not None
                else ""
            )
            warn(
                f"GitHub rate limit: {rl['remaining']}/{rl['limit']} remaining{suffix}",
                C.GREY,
            )

    return 3 if errors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        warn("\nAborted by user.")
        sys.exit(130)
