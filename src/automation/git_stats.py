#!/usr/bin/env python3
r"""
=====================================================================================
SCRIPT NAME:      git_stats.py
VERSION:          1.0

DESCRIPTION:
    Per-author commit statistics for a git repository, from a single
    self-contained script.

    Reports commits, files changed, insertions, deletions, net lines, active
    days, first/last commit and each contributor's share of the total. Also
    computes a bus-factor estimate (how many authors cover 50% / 80% of
    commits) and, with --activity, a commit histogram by day, week, month or
    year.

    Everything comes from `git log --numstat`; there is no server, no API key
    and no network access. Output is a human-readable report by default, or
    JSON / JSONL / CSV for piping.

USAGE
-----
    python src/automation/git_stats.py
    python src/automation/git_stats.py -C /path/to/repo
    python src/automation/git_stats.py -C /srv/git/project.git
    python src/automation/git_stats.py --repo ~/code/project
    python src/automation/git_stats.py --since "6 months ago"
    python src/automation/git_stats.py --since 2024-01-01 --until 2024-12-31
    python src/automation/git_stats.py --path src/ --path tests/
    python src/automation/git_stats.py --author alice --exclude-author '\[bot\]'
    python src/automation/git_stats.py --sort insertions --reverse
    python src/automation/git_stats.py --activity month
    python src/automation/git_stats.py --json
    python src/automation/git_stats.py --jsonl --fields name,email,commits
    python src/automation/git_stats.py --csv stats.csv
    python src/automation/git_stats.py --self-test

WHICH REPOSITORY
----------------
    Three ways to choose the repository, in order of precedence:

    1. -C DIR / --repo DIR
         Explicit path. `~` is expanded, relative paths are resolved from
         the current working directory. The path must be either a worktree
         (contains a .git entry) or a bare repository (contains HEAD,
         objects/ and refs/ at its top level).

    2. Bare invocation, from inside a working tree
         The script walks upward from the current directory until it finds
         a .git entry, exactly like `git status`. Running it from anywhere
         inside a repo - including deep subdirectories - finds the root.

    3. Nothing
         If neither -C is given nor an enclosing repo is found, the script
         exits with code 2 and prints:

             ERROR: not inside a git repository (use -C DIR to point at one).

    Bare repositories are only discoverable via -C, never via the upward
    walk. That mirrors git's own behaviour and avoids surprising matches.

NOTES
-----
    - --since / --until use git's own date parser and are evaluated against
      the *commit* date by default (this is git's behaviour, not a choice
      made here). Use --date to control which date is displayed and used for
      activity bucketing.
    - Merge commits are excluded by default. Pass --merges to include them.
    - Author identity is grouped by lowercased email by default. Use
      --by name or --by name+email to change that, and --use-mailmap to let
      git's .mailmap file resolve aliases.

REQUIREMENTS
------------
    - Python 3.8+
    - git on PATH (the script shells out to `git log`)

Copyright (c) 2026 Jericho Crosby (Chalwk)
LICENSE: MIT
=====================================================================================
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Counter as CounterType,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)


__version__ = "1.0"


# Enable ANSI escape sequences on Windows 10 console
if os.name == "nt":
    os.system("")

# Box-drawing characters / bars must never crash on a legacy code page.
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


USE_COLOR = False


def paint(text: Any, code: str) -> str:
    text = str(text)
    return f"{code}{text}{C.RESET}" if USE_COLOR and code else text


def pad(text: Any, width: int, code: str = "", align: str = "l") -> str:
    """Pad before colouring so ANSI codes don't wreck column alignment."""
    s = str(text)
    s = s.rjust(width) if align == "r" else s.ljust(width)
    return paint(s, code)


def warn(msg: str, code: str = C.YELLOW) -> None:
    print(paint(msg, code), file=sys.stderr)


# ============================================================================
# CONSTANTS
# ============================================================================
FIELD_SEP = "\x1f"
RECORD_SEP = "\x1e"

# %x1e = record separator, %x1f = field separator. Both are control chars
# that never appear in a real author name or email.
GIT_LOG_FORMAT = (
    f"{RECORD_SEP}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%at{FIELD_SEP}%ct"
)

SPARK_CHARS = "▁▂▃▄▅▆▇█"

CSV_FIELDS: Tuple[str, ...] = (
    "name",
    "email",
    "commits",
    "share",
    "files",
    "insertions",
    "deletions",
    "lines",
    "net",
    "active_days",
    "first_commit",
    "last_commit",
)

SORT_EXTRACTORS: Dict[str, Any] = {
    "name": lambda a: (a.name.lower(), a.email.lower()),
    "commits": lambda a: a.commits,
    "files": lambda a: a.files_changed,
    "insertions": lambda a: a.insertions,
    "deletions": lambda a: a.deletions,
    "lines": lambda a: a.lines_changed,
    "net": lambda a: a.net,
    "active": lambda a: a.active_day_count,
    "first": lambda a: a.first_ts,
    "last": lambda a: a.last_ts,
}

SORT_KEYS: Tuple[str, ...] = tuple(SORT_EXTRACTORS)


# ============================================================================
# ERRORS
# ============================================================================
class GitError(RuntimeError):
    """Raised when git itself fails (non-zero exit) or cannot be launched."""


# ============================================================================
# DATA MODELS
# ============================================================================
@dataclass
class RawCommit:
    """One commit as parsed from `git log --numstat`."""

    sha: str
    name: str
    email: str
    author_ts: int
    commit_ts: int
    files: List[Tuple[Optional[int], Optional[int], str]] = field(default_factory=list)


@dataclass
class AuthorStats:
    """Aggregated statistics for one contributor."""

    key: str
    name: str
    email: str
    commits: int = 0
    files_changed: int = 0
    insertions: int = 0
    deletions: int = 0
    first_ts: int = 0
    last_ts: int = 0
    active_days: Set[str] = field(default_factory=set)

    @property
    def lines_changed(self) -> int:
        return self.insertions + self.deletions

    @property
    def net(self) -> int:
        return self.insertions - self.deletions

    @property
    def active_day_count(self) -> int:
        return len(self.active_days)


@dataclass
class CollectOptions:
    repo: Path
    ref: str = "HEAD"
    since: Optional[str] = None
    until: Optional[str] = None
    paths: Sequence[str] = ()
    author: Optional[str] = None
    exclude_author: Optional[str] = None
    no_merges: bool = True
    use_mailmap: bool = False
    author_key: str = "email"
    use_commit_date: bool = False
    utc: bool = False


@dataclass
class Report:
    repo: Path
    ref: str
    authors: List[AuthorStats]
    timestamps: List[int]
    commits: int
    files_changed: int
    insertions: int
    deletions: int
    first_ts: int
    last_ts: int


# ============================================================================
# TIME HELPERS
# ============================================================================
def to_datetime(ts: int, utc: bool) -> datetime:
    """Epoch seconds -> tz-aware datetime (local by default, UTC on request)."""
    if utc:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    try:
        return datetime.fromtimestamp(ts).astimezone()
    except (OSError, OverflowError, ValueError):
        return datetime.fromtimestamp(ts, tz=timezone.utc)


def iso(ts: int, utc: bool) -> str:
    if ts <= 0:
        return ""
    try:
        return to_datetime(ts, utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return ""


def fmt_date(ts: int, utc: bool) -> str:
    if ts <= 0:
        return "-"
    try:
        return to_datetime(ts, utc).strftime("%Y-%m-%d")
    except (OSError, OverflowError, ValueError):
        return "-"


# ============================================================================
# GIT PLUMBING
# ============================================================================
def looks_like_git_repo(path: Path) -> bool:
    """True if `path` is a git worktree or a bare repository.

    Worktree: contains a `.git` entry (directory, or a file for worktrees
    and submodules).

    Bare repo: HEAD, objects/ and refs/ all live at the top level. These
    are the minimum markers `git log` needs; we don't try to be cleverer
    than that.
    """
    if (path / ".git").exists():
        return True
    return (
        (path / "HEAD").is_file()
        and (path / "objects").is_dir()
        and (path / "refs").is_dir()
    )


def find_repo_root(start: Path) -> Optional[Path]:
    """Walk upward from `start` until a worktree root is found.

    Mirrors `git status`: running from anywhere inside a working tree
    (including deep subdirectories) finds the repo root. Returns None if
    no enclosing worktree is found.

    Bare repositories are not discovered here - they have no `.git`
    subdirectory to find. Use -C DIR to point at one explicitly.
    """
    try:
        current = start.resolve()
    except OSError:
        return None
    for candidate in (current, *current.parents):
        # .git can be a directory (normal) or a file (worktree / submodule).
        if (candidate / ".git").exists():
            return candidate
    return None


def git_capture(repo: Path, args: Sequence[str]) -> Tuple[int, str, str]:
    """Run git, returning (returncode, stdout, stderr). Never raises on rc!=0."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except FileNotFoundError:
        raise GitError("git executable not found on PATH") from None
    except subprocess.SubprocessError as exc:
        raise GitError(f"git failed: {exc}") from None
    return proc.returncode, proc.stdout, proc.stderr


def git_stream(repo: Path, args: Sequence[str]) -> Iterator[str]:
    """Yield stdout lines from `git -C repo <args>`.

    stderr is drained on a background thread so a full pipe can't deadlock
    the child. A non-zero exit status raises GitError once the stream is
    exhausted - but not if the caller closes the generator early.
    """
    cmd = ["git", "-C", str(repo), *args]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except FileNotFoundError:
        raise GitError("git executable not found on PATH") from None

    stderr_lines: List[str] = []

    def drain() -> None:
        stream = proc.stderr
        if stream is None:
            return
        try:
            for line in stream:
                stderr_lines.append(line)
        except (OSError, ValueError):
            pass

    drainer = threading.Thread(target=drain, name="git-stderr", daemon=True)
    drainer.start()

    completed = False
    try:
        out = proc.stdout
        if out is not None:
            for line in out:
                yield line
        completed = True
    finally:
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        drainer.join(timeout=5)

    # If the consumer broke out early we silently return; the caller is
    # already handling its own control flow (Ctrl+C, early exit, etc).
    if not completed:
        return

    if proc.returncode:
        message = (
            "".join(stderr_lines).strip() or f"git exited with status {proc.returncode}"
        )
        raise GitError(message)


def current_ref(repo: Path) -> str:
    code, out, _ = git_capture(repo, ["rev-parse", "--abbrev-ref", "HEAD"])
    ref = out.strip()
    if code != 0 or not ref:
        return "HEAD"
    return ref


def is_shallow(repo: Path) -> bool:
    code, out, _ = git_capture(repo, ["rev-parse", "--is-shallow-repository"])
    if code == 0:
        return out.strip() == "true"

    code, out, _ = git_capture(repo, ["rev-parse", "--git-dir"])
    if code != 0:
        return False
    git_dir = Path(out.strip())
    if not git_dir.is_absolute():
        git_dir = repo / git_dir
    return (git_dir / "shallow").exists()


# ============================================================================
# PARSING
# ============================================================================
def iter_raw_commits(lines: Iterable[str]) -> Iterator[RawCommit]:
    """Parse the output of `git log --format=<GIT_LOG_FORMAT> --numstat`.

    Layout per commit::

        <RS>sha<US>name<US>email<US>atime<US>ctime
        <blank>
        10\t2\tpath/to/file
        -\t-\tpath/to/binary

    Binary files report "-" for both counts and are recorded as None.
    """
    current: Optional[RawCommit] = None

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            continue

        if line.startswith(RECORD_SEP):
            if current is not None:
                yield current
                current = None

            parts = line[1:].split(FIELD_SEP)
            if len(parts) < 5:
                # Malformed header: skip the record rather than aborting.
                continue

            sha, name, email, at_s, ct_s = parts[:5]
            try:
                author_ts = int(at_s)
            except ValueError:
                author_ts = 0
            try:
                commit_ts = int(ct_s)
            except ValueError:
                commit_ts = 0

            current = RawCommit(sha, name, email, author_ts, commit_ts)
            continue

        if current is None:
            continue

        # numstat line. split("\t", 2) keeps paths containing tabs intact.
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue

        add_s, del_s, path = parts
        add = int(add_s) if add_s.isdigit() else None
        dele = int(del_s) if del_s.isdigit() else None
        current.files.append((add, dele, path))

    if current is not None:
        yield current


def author_key_for(mode: str):
    """Return a function that maps a RawCommit to its grouping key."""
    if mode == "name":

        def key_by_name(commit: RawCommit) -> str:
            return (commit.name or commit.email).strip().lower()

        return key_by_name

    if mode == "name+email":

        def key_by_both(commit: RawCommit) -> str:
            name = commit.name.strip().lower()
            email = commit.email.strip().lower()
            return f"{name}\x00{email}"

        return key_by_both

    def key_by_email(commit: RawCommit) -> str:
        return (commit.email or commit.name).strip().lower()

    return key_by_email


# ============================================================================
# COLLECTION
# ============================================================================
def collect(options: CollectOptions) -> Report:
    """Run `git log` and aggregate everything into a Report."""
    git_args: List[str] = [
        "log",
        f"--format={GIT_LOG_FORMAT}",
        "--numstat",
    ]
    if options.no_merges:
        git_args.append("--no-merges")
    if options.since:
        git_args.append(f"--since={options.since}")
    if options.until:
        git_args.append(f"--until={options.until}")
    if options.author:
        git_args.append(f"--author={options.author}")
    if options.use_mailmap:
        git_args.append("--use-mailmap")
    git_args.append(options.ref or "HEAD")
    if options.paths:
        git_args.append("--")
        git_args.extend(options.paths)

    key_fn = author_key_for(options.author_key)
    exclude_re = (
        re.compile(options.exclude_author, re.IGNORECASE)
        if options.exclude_author
        else None
    )

    authors: Dict[str, AuthorStats] = {}
    timestamps: List[int] = []
    first_ts = 0
    last_ts = 0

    for commit in iter_raw_commits(git_stream(options.repo, git_args)):
        if exclude_re is not None:
            haystack = f"{commit.name} <{commit.email}>"
            if exclude_re.search(haystack):
                continue

        key = key_fn(commit)
        stats = authors.get(key)
        if stats is None:
            stats = AuthorStats(key=key, name=commit.name, email=commit.email)
            authors[key] = stats

        stats.commits += 1
        stats.files_changed += len(commit.files)
        for add, dele, _path in commit.files:
            if add is not None:
                stats.insertions += add
            if dele is not None:
                stats.deletions += dele

        ts = commit.commit_ts if options.use_commit_date else commit.author_ts
        if ts > 0:
            if stats.first_ts == 0 or ts < stats.first_ts:
                stats.first_ts = ts
            if ts > stats.last_ts:
                stats.last_ts = ts
            stats.active_days.add(to_datetime(ts, options.utc).strftime("%Y-%m-%d"))
            timestamps.append(ts)
            if first_ts == 0 or ts < first_ts:
                first_ts = ts
            if ts > last_ts:
                last_ts = ts

    return Report(
        repo=options.repo,
        ref=options.ref,
        authors=list(authors.values()),
        timestamps=timestamps,
        commits=sum(a.commits for a in authors.values()),
        files_changed=sum(a.files_changed for a in authors.values()),
        insertions=sum(a.insertions for a in authors.values()),
        deletions=sum(a.deletions for a in authors.values()),
        first_ts=first_ts,
        last_ts=last_ts,
    )


# ============================================================================
# ANALYSIS
# ============================================================================
def bus_factor(sorted_counts: Sequence[int], threshold: float) -> int:
    """Minimum number of top authors whose commits cover `threshold` of all."""
    total = sum(sorted_counts)
    if total <= 0:
        return 0
    running = 0
    for index, count in enumerate(sorted_counts, 1):
        running += count
        if running / total >= threshold:
            return index
    return len(sorted_counts)


def activity(
    timestamps: Sequence[int], period: str, utc: bool
) -> List[Tuple[str, int]]:
    """Bucket commit timestamps into (period_label, count), sorted ascending."""
    counter: CounterType[str] = Counter()
    for ts in timestamps:
        dt = to_datetime(ts, utc)
        if period == "day":
            label = dt.strftime("%Y-%m-%d")
        elif period == "week":
            year, week, _ = dt.isocalendar()
            label = f"{year}-W{week:02d}"
        elif period == "year":
            label = dt.strftime("%Y")
        else:  # month
            label = dt.strftime("%Y-%m")
        counter[label] += 1
    return sorted(counter.items())


def sort_authors(
    authors: Sequence[AuthorStats], key: str, reverse: bool
) -> List[AuthorStats]:
    """Sort by `key`. Numeric keys default to descending; `name` to ascending."""
    extractor = SORT_EXTRACTORS.get(key, SORT_EXTRACTORS["commits"])
    descending = key != "name"
    return sorted(authors, key=extractor, reverse=(descending != reverse))


# ============================================================================
# RECORD / SUMMARY BUILDERS
# ============================================================================
def author_record(author: AuthorStats, total_commits: int, utc: bool) -> Dict[str, Any]:
    share = (author.commits / total_commits) if total_commits else 0.0
    return {
        "name": author.name,
        "email": author.email,
        "commits": author.commits,
        "share": round(share, 4),
        "files": author.files_changed,
        "insertions": author.insertions,
        "deletions": author.deletions,
        "lines": author.lines_changed,
        "net": author.net,
        "active_days": author.active_day_count,
        "first_commit": iso(author.first_ts, utc),
        "last_commit": iso(author.last_ts, utc),
    }


def build_summary(report: Report, options: CollectOptions) -> Dict[str, Any]:
    counts = sorted((a.commits for a in report.authors), reverse=True)
    return {
        "commits": report.commits,
        "contributors": len(report.authors),
        "files_changed": report.files_changed,
        "insertions": report.insertions,
        "deletions": report.deletions,
        "net": report.insertions - report.deletions,
        "first_commit": iso(report.first_ts, options.utc) or None,
        "last_commit": iso(report.last_ts, options.utc) or None,
        "bus_factor_50": bus_factor(counts, 0.50) if counts else 0,
        "bus_factor_80": bus_factor(counts, 0.80) if counts else 0,
    }


def resolve_fields(requested: Optional[str], default: Sequence[str]) -> List[str]:
    """Split a comma-separated --fields value; drop unknowns with a warning."""
    if not requested:
        return list(default)
    known = set(default)
    result: List[str] = []
    unknown: List[str] = []
    for name in requested.split(","):
        name = name.strip()
        if not name or name in result:
            continue
        if name not in known:
            unknown.append(name)
            continue
        result.append(name)
    if unknown:
        warn(f"Ignoring unknown field(s): {', '.join(unknown)}")
    return result or list(default)


# ============================================================================
# RENDER: HUMAN
# ============================================================================
def human_int(n: int) -> str:
    return f"{n:,}"


def human_signed(n: int) -> str:
    return f"{'+' if n >= 0 else '-'}{abs(n):,}"


def human_share(count: int, total: int) -> str:
    if total <= 0:
        return "-"
    return f"{count / total * 100:.1f}%"


def sparkline(values: Sequence[int]) -> str:
    """A one-line unicode sparkline. Uniform series render as a flat band."""
    if not values:
        return ""
    hi, lo = max(values), min(values)
    if hi == lo:
        char = SPARK_CHARS[-1] if hi > 0 else SPARK_CHARS[0]
        return char * len(values)
    span = hi - lo
    scale = len(SPARK_CHARS) - 1
    return "".join(SPARK_CHARS[round((v - lo) / span * scale)] for v in values)


def author_label(author: AuthorStats) -> str:
    if author.email:
        return f"{author.name} <{author.email}>"
    return author.name or author.email or "(unknown)"


def terminal_width(default: int = 120) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def render_overview(report: Report, options: CollectOptions) -> None:
    rows: List[Tuple[str, str]] = [
        ("Commits", human_int(report.commits)),
        ("Contributors", human_int(len(report.authors))),
        ("Files changed", human_int(report.files_changed)),
        ("Insertions", f"+{report.insertions:,}"),
        ("Deletions", f"-{report.deletions:,}"),
        ("Net", human_signed(report.insertions - report.deletions)),
    ]
    if report.first_ts:
        rows.append(("First commit", fmt_date(report.first_ts, options.utc)))
    if report.last_ts:
        rows.append(("Last commit", fmt_date(report.last_ts, options.utc)))

    label_width = max(len(label) for label, _ in rows) + 2
    value_width = max(len(value) for _, value in rows)

    print(paint("OVERVIEW", C.BOLD))
    for label, value in rows:
        print(f"  {paint(label.ljust(label_width), C.CYAN)}{value.rjust(value_width)}")
    print()


def render_bus_factor(report: Report) -> None:
    print(paint("BUS FACTOR", C.BOLD))

    counts = sorted((a.commits for a in report.authors), reverse=True)
    if not counts or sum(counts) <= 0:
        print("  (no commits)")
        print()
        return

    total = sum(counts)
    bf50 = bus_factor(counts, 0.50)
    bf80 = bus_factor(counts, 0.80)
    share50 = sum(counts[:bf50]) / total * 100
    share80 = sum(counts[:bf80]) / total * 100

    label50 = f"Top {bf50} author" + ("s" if bf50 != 1 else "")
    label80 = f"Top {bf80} author" + ("s" if bf80 != 1 else "")
    width = max(len(label50), len(label80)) + 1

    print(f"  {label50.ljust(width)} cover {share50:5.1f}% of commits  (>= 50%)")
    print(f"  {label80.ljust(width)} cover {share80:5.1f}% of commits  (>= 80%)")

    top_share = counts[0] / total
    if top_share >= 0.50:
        risk, code = "HIGH", C.RED
        note = "a single contributor dominates this repository."
    elif top_share >= 0.25:
        risk, code = "MEDIUM", C.YELLOW
        note = "one contributor holds a large share of the commits."
    else:
        risk, code = "LOW", C.GREEN
        note = "no single contributor dominates."
    print(f"  {paint('Risk:', C.BOLD)} {paint(risk, code)} - {note}")
    print()


def render_contributors(
    report: Report,
    options: CollectOptions,
    args: argparse.Namespace,
    authors: Sequence[AuthorStats],
    total_commits: int,
) -> None:
    print(paint(f"CONTRIBUTORS (by {args.sort})", C.BOLD))

    if not authors:
        print("  (none)")
        print()
        return

    # Work out how wide the author column can be on this terminal.
    fixed = 3 + 9 + 7 + 10 + 10 + 10 + 7 + 12 + 2 + 2 * 8
    author_width = max(16, min(34, terminal_width() - fixed))

    columns: List[Tuple[str, int, str]] = [
        ("#", 3, "r"),
        ("AUTHOR", author_width, "l"),
        ("COMMITS", 9, "r"),
        ("SHARE", 7, "r"),
        ("+LINES", 10, "r"),
        ("-LINES", 10, "r"),
        ("NET", 10, "r"),
        ("ACTIVE", 7, "r"),
        ("LAST", 12, "r"),
    ]
    header = "  " + "  ".join(
        paint(
            text.rjust(width) if align == "r" else text.ljust(width),
            C.BOLD,
        )
        for text, width, align in columns
    )
    print(header)

    for rank, author in enumerate(authors, 1):
        label = author_label(author)
        if len(label) > author_width:
            label = label[: author_width - 1] + "…"

        net = author.net
        if net > 0:
            net_color = C.GREEN
        elif net < 0:
            net_color = C.RED
        else:
            net_color = C.GREY

        cells = [
            pad(rank, 3, C.GREY, "r"),
            pad(label, author_width, "", "l"),
            pad(human_int(author.commits), 9, "", "r"),
            pad(human_share(author.commits, total_commits), 7, "", "r"),
            pad(
                f"+{author.insertions:,}",
                10,
                C.GREEN if author.insertions else C.GREY,
                "r",
            ),
            pad(
                f"-{author.deletions:,}",
                10,
                C.RED if author.deletions else C.GREY,
                "r",
            ),
            pad(human_signed(net), 10, net_color, "r"),
            pad(human_int(author.active_day_count), 7, "", "r"),
            pad(fmt_date(author.last_ts, options.utc), 12, "", "r"),
        ]
        print("  " + "  ".join(cells))
    print()


def render_activity(
    buckets: Sequence[Tuple[str, int]], period: str, limit: int
) -> None:
    if not buckets:
        return

    shown = list(buckets)
    truncated = 0
    if limit and len(shown) > limit:
        truncated = len(shown) - limit
        shown = shown[-limit:]

    print(paint(f"ACTIVITY ({period})", C.BOLD))

    values = [count for _, count in shown]
    hi = max(values) if values else 0
    label_width = max(len(label) for label, _ in shown)
    count_width = max(len(human_int(v)) for v in values)

    print(f"  {paint('Trend', C.CYAN)}  {paint(sparkline(values), C.MAGENTA)}")
    if truncated:
        print(
            paint(
                f"  (showing the most recent {len(shown)} of {len(buckets)} periods; "
                f"use --activity-limit 0 to see all)",
                C.GREY,
            )
        )
    print()

    bar_width = 24
    for label, count in shown:
        filled = round(count / hi * bar_width) if hi else 0
        bar = paint("█" * filled, C.BLUE) if filled else ""
        print(
            f"  {paint(label.ljust(label_width), C.CYAN)}  "
            f"{human_int(count).rjust(count_width)}  {bar}"
        )
    print()


def render_human(
    report: Report,
    options: CollectOptions,
    args: argparse.Namespace,
    authors: Sequence[AuthorStats],
    total_commits: int,
) -> None:
    divider = paint("=" * 80, C.GREY)
    date_source = "committer date" if options.use_commit_date else "author date"
    tz_label = "UTC" if options.utc else "local time"

    print(divider)
    print(f"{paint('REPOSITORY', C.BOLD)}  {report.repo}")
    print(f"{paint('REF', C.BOLD)}         {report.ref}")
    if args.since or args.until:
        parts = []
        if args.since:
            parts.append(f"since {args.since}")
        if args.until:
            parts.append(f"until {args.until}")
        print(f"{paint('RANGE', C.BOLD)}       {'  '.join(parts)}")
    if args.path:
        print(f"{paint('PATHS', C.BOLD)}       {', '.join(args.path)}")
    if args.author:
        print(f"{paint('AUTHOR', C.BOLD)}      {args.author}")
    if args.exclude_author:
        print(f"{paint('EXCLUDE', C.BOLD)}     {args.exclude_author}")
    print(f"{paint('DATES', C.BOLD)}       {date_source}, {tz_label}")
    print(divider)
    print()

    if is_shallow(report.repo):
        print(
            paint(
                "  Note: this is a shallow clone - history may be truncated.",
                C.YELLOW,
            )
        )
        print()

    render_overview(report, options)
    render_bus_factor(report)
    render_contributors(report, options, args, authors, total_commits)

    if args.activity:
        render_activity(
            activity(report.timestamps, args.activity, options.utc),
            args.activity,
            args.activity_limit,
        )

    total_authors = len(report.authors)
    if not args.quiet and len(authors) < total_authors:
        print(
            paint(
                f"  Showing {len(authors)} of {total_authors} contributors "
                f"(use --top 0 to show all).",
                C.GREY,
            )
        )
        print()


# ============================================================================
# RENDER: CSV / JSON
# ============================================================================
def write_csv(
    path: str,
    rows: Sequence[Dict[str, Any]],
    fields: Sequence[str],
    no_header: bool,
) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields), extrasaction="ignore")
        if not no_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})


# ============================================================================
# SELF TEST
# ============================================================================
def _self_test_scratch_repo() -> bool:
    """Build a throwaway repo and check that collect() sees what it should."""
    import tempfile

    try:
        with tempfile.TemporaryDirectory(prefix="git-stats-test-") as tmp:
            repo = Path(tmp)

            def run_git(*args: str, env: Optional[Dict[str, str]] = None) -> None:
                subprocess.run(
                    ["git", "-C", str(repo), *args],
                    check=True,
                    capture_output=True,
                    text=True,
                    env=env,
                )

            run_git("init", "-q")
            run_git("config", "user.name", "Alice")
            run_git("config", "user.email", "alice@example.com")
            run_git("config", "commit.gpgsign", "false")

            def commit(filename: str, content: str, name: str, email: str) -> None:
                (repo / filename).write_text(content, encoding="utf-8")
                run_git("add", filename)
                env = {
                    **os.environ,
                    "GIT_AUTHOR_NAME": name,
                    "GIT_AUTHOR_EMAIL": email,
                    "GIT_COMMITTER_NAME": name,
                    "GIT_COMMITTER_EMAIL": email,
                }
                run_git("commit", "-q", "-m", f"add {filename}", env=env)

            commit("a.txt", "one\n", "Alice", "alice@example.com")
            commit("b.txt", "two\nthree\n", "Bob", "bob@example.com")
            commit("c.txt", "four\n", "Alice", "alice@example.com")

            report = collect(CollectOptions(repo=repo))
            if report.commits != 3:
                return False
            if len(report.authors) != 2:
                return False

            alice = next(
                (a for a in report.authors if a.email == "alice@example.com"),
                None,
            )
            bob = next(
                (a for a in report.authors if a.email == "bob@example.com"),
                None,
            )
            if alice is None or alice.commits != 2:
                return False
            if bob is None or bob.commits != 1:
                return False
            # a.txt(1 line) + c.txt(1 line)
            if alice.insertions != 2:
                return False
            # b.txt(2 lines)
            if bob.insertions != 2:
                return False
            return True
    except Exception as exc:
        print(f"    (scratch repo error: {type(exc).__name__}: {exc})")
        return False


def run_self_test() -> int:
    print(f"git_stats {__version__} self-test")

    failures = 0

    def check(label: str, condition: Any) -> None:
        nonlocal failures
        ok = bool(condition)
        print(f"  {'PASS' if ok else 'FAIL':<4} {label}")
        if not ok:
            failures += 1

    # --- parsing -----------------------------------------------------------
    sample = (
        RECORD_SEP
        + "abc123"
        + FIELD_SEP
        + "Alice"
        + FIELD_SEP
        + "alice@example.com"
        + FIELD_SEP
        + "1700000000"
        + FIELD_SEP
        + "1700000001\n"
        + "\n"
        + "10\t2\tsrc/a.py\n"
        + "3\t0\tsrc/b.py\n"
        + RECORD_SEP
        + "def456"
        + FIELD_SEP
        + "Bob"
        + FIELD_SEP
        + "bob@example.com"
        + FIELD_SEP
        + "1700000100"
        + FIELD_SEP
        + "1700000101\n"
        + "\n"
        + "-\t-\tlogo.png\n"
    )
    commits = list(iter_raw_commits(sample.split("\n")))

    check("parse.commit_count", len(commits) == 2)
    check("parse.sha", commits[0].sha == "abc123")
    check("parse.author_name", commits[0].name == "Alice")
    check("parse.author_email", commits[0].email == "alice@example.com")
    check("parse.author_ts", commits[0].author_ts == 1700000000)
    check("parse.file_count", len(commits[0].files) == 2)
    check("parse.insertions", commits[0].files[0][0] == 10)
    check("parse.deletions", commits[0].files[1][1] == 0)
    check("parse.binary_marker", commits[1].files[0][0] is None)
    check("parse.binary_path", commits[1].files[0][2] == "logo.png")

    # --- author key --------------------------------------------------------
    a1 = RawCommit("a", "Alice", "alice@example.com", 1, 1)
    a2 = RawCommit("b", "alice", "ALICE@example.com", 2, 2)
    bob = RawCommit("c", "Bob", "bob@example.com", 3, 3)
    by_email = author_key_for("email")
    by_name = author_key_for("name")
    check("key.email_case_insensitive", by_email(a1) == by_email(a2))
    check("key.email_differs", by_email(a1) != by_email(bob))
    check("key.name_groups", by_name(a1) == by_name(a2))

    # --- bus factor --------------------------------------------------------
    check("bus.single", bus_factor([10, 0, 0], 0.50) == 1)
    check("bus.even_50", bus_factor([5, 5, 5, 5], 0.50) == 2)
    check("bus.even_80", bus_factor([5, 5, 5, 5], 0.80) == 4)
    check("bus.empty", bus_factor([], 0.50) == 0)
    check("bus.zero_total", bus_factor([0, 0], 0.50) == 0)

    # --- sparkline ---------------------------------------------------------
    check("spark.empty", sparkline([]) == "")
    check("spark.uniform_nonzero", set(sparkline([3, 3, 3])) == {SPARK_CHARS[-1]})
    check("spark.uniform_zero", set(sparkline([0, 0])) == {SPARK_CHARS[0]})
    rising = sparkline([0, 1, 2, 3, 4, 5, 6, 7])
    check("spark.rising_length", len(rising) == 8)
    check("spark.rising_first", rising[0] == SPARK_CHARS[0])
    check("spark.rising_last", rising[-1] == SPARK_CHARS[-1])

    # --- formatting --------------------------------------------------------
    check("fmt.int", human_int(1234567) == "1,234,567")
    check("fmt.signed_pos", human_signed(42) == "+42")
    check("fmt.signed_neg", human_signed(-42) == "-42")
    check("fmt.share", human_share(1, 4) == "25.0%")
    check("fmt.share_zero_total", human_share(1, 0) == "-")

    # --- activity bucketing ------------------------------------------------
    # 2024-01-01 00:00:00 UTC, 2024-01-01 01:00:00 UTC, 2024-02-01 00:00:00 UTC
    ts1, ts2, ts3 = 1704067200, 1704070800, 1706745600
    daily = activity([ts1, ts2, ts3], "day", utc=True)
    check("activity.day_count", len(daily) == 2)
    check("activity.day_first", daily[0] == ("2024-01-01", 2))
    monthly = activity([ts1, ts2, ts3], "month", utc=True)
    check("activity.month_count", len(monthly) == 2)
    check("activity.month_first", monthly[0] == ("2024-01", 2))
    weekly = activity([ts1, ts2, ts3], "week", utc=True)
    check("activity.week_labels_unique", len({label for label, _ in weekly}) == 2)

    # --- fields ------------------------------------------------------------
    check(
        "fields.preserve_order",
        resolve_fields("email,name", CSV_FIELDS) == ["email", "name"],
    )
    check(
        "fields.default_passthrough",
        resolve_fields(None, CSV_FIELDS) == list(CSV_FIELDS),
    )
    check(
        "fields.drop_unknown",
        resolve_fields("name,nope", CSV_FIELDS) == ["name"],
    )

    # --- argparse surface --------------------------------------------------
    ns = parse_args([])
    check("args.has_path", hasattr(ns, "path"))
    check("args.has_paths_typo_absent", not hasattr(ns, "paths"))
    check("args.has_path_default", ns.path == [])

    # --- repo detection ----------------------------------------------------
    check(
        "repo.looks_like.empty_dir",
        not looks_like_git_repo(Path("/definitely/not/here")),
    )
    check(
        "repo.looks_like.worktree",
        looks_like_git_repo(Path(__file__).resolve().parent),
    )

    # --- end-to-end (needs git) --------------------------------------------
    if shutil.which("git"):
        check("e2e.scratch_repo", _self_test_scratch_repo())
    else:
        print("  SKIP e2e.scratch_repo (git not found on PATH)")

    print()
    print(f"Result: {'PASS' if failures == 0 else f'{failures} failure(s)'}")
    return 0 if failures == 0 else 1


# ============================================================================
# ARGPARSE
# ============================================================================
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="git_stats.py",
        description=(
            "Per-author commit statistics for a git repository. "
            "By default, runs against the repo enclosing the current "
            "directory (searched upward, like `git status`). Use -C DIR "
            "to point at a different one - including a bare repo."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Which repository:\n"
            "  Default   search upward from cwd for a .git entry\n"
            "            (same as `git status`; works from subdirectories)\n"
            "  Override  -C DIR / --repo DIR\n"
            "  Bare      -C /srv/git/project.git  (only via -C)\n"
            "\n"
            "Examples:\n"
            "  python git_stats.py\n"
            "  python git_stats.py -C ~/code/project\n"
            "  python git_stats.py -C /srv/git/project.git --json\n"
            "  python git_stats.py --since '6 months ago' --activity month\n"
            "  python git_stats.py --path src/ --path tests/ --sort lines\n"
            "  python git_stats.py --activity month --top 10\n"
            "  python git_stats.py --csv stats.csv --fields name,email,commits\n"
            "  python git_stats.py --self-test\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"git_stats.py {__version__}",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline tests and exit.",
    )
    parser.add_argument(
        "-C",
        "--repo",
        metavar="DIR",
        help=(
            "Repository directory. `~` is expanded; relative paths are "
            "resolved from cwd. Accepts a worktree (has a .git entry) or "
            "a bare repository. Default: search upward from cwd for a "
            ".git entry, like `git status`."
        ),
    )

    src = parser.add_argument_group("history selection")
    src.add_argument(
        "--ref",
        default="HEAD",
        help="Branch, tag, or commit range (default: HEAD).",
    )
    src.add_argument(
        "--since",
        metavar="DATE",
        help="Limit to commits after DATE (git date syntax).",
    )
    src.add_argument(
        "--until",
        metavar="DATE",
        help="Limit to commits before DATE (git date syntax).",
    )
    src.add_argument(
        "--path",
        "-p",
        action="append",
        default=[],
        metavar="PATH",
        help="Limit to PATH. Repeatable.",
    )
    src.add_argument(
        "--author",
        metavar="PATTERN",
        help="Only commits whose author matches PATTERN (git --author).",
    )
    src.add_argument(
        "--exclude-author",
        metavar="REGEX",
        help="Drop commits whose 'Name <email>' matches REGEX.",
    )
    src.add_argument(
        "--merges",
        action="store_true",
        help="Include merge commits (excluded by default).",
    )
    src.add_argument(
        "--use-mailmap",
        action="store_true",
        help="Honour .mailmap when resolving authors.",
    )
    src.add_argument(
        "--by",
        choices=["email", "name", "name+email"],
        default="email",
        help="How to group contributors (default: email).",
    )
    src.add_argument(
        "--date",
        choices=["author", "commit"],
        default="author",
        help="Which date to display and bucket (default: author).",
    )
    src.add_argument(
        "--utc",
        action="store_true",
        help="Display dates in UTC (default: local time).",
    )

    out = parser.add_argument_group("output")
    out.add_argument(
        "--sort",
        choices=SORT_KEYS,
        default="commits",
        help="Sort contributors by this field (default: commits).",
    )
    out.add_argument(
        "--reverse",
        action="store_true",
        help="Reverse the sort order.",
    )
    out.add_argument(
        "--top",
        type=int,
        metavar="N",
        help="Show only the top N contributors.",
    )
    out.add_argument(
        "--min-commits",
        type=int,
        default=1,
        metavar="N",
        help="Hide contributors with fewer than N commits (default: 1).",
    )
    out.add_argument(
        "--activity",
        choices=["day", "week", "month", "year"],
        help="Also print a commit histogram by period.",
    )
    out.add_argument(
        "--activity-limit",
        type=int,
        default=40,
        metavar="N",
        help="Show at most N activity buckets; 0 = all (default: 40).",
    )

    fmt = out.add_mutually_exclusive_group()
    fmt.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON to stdout.",
    )
    fmt.add_argument(
        "--jsonl",
        action="store_true",
        help="Print one JSON object per contributor.",
    )

    out.add_argument(
        "--csv",
        metavar="PATH",
        help="Also write the contributor table to a CSV file.",
    )
    out.add_argument(
        "--fields",
        metavar="LIST",
        help="Comma-separated subset of fields for CSV/JSON output.",
    )
    out.add_argument(
        "--no-header",
        action="store_true",
        help="Omit the header row when writing CSV.",
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

    return parser.parse_args(argv)


# ============================================================================
# MAIN
# ============================================================================
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

    if shutil.which("git") is None:
        warn("ERROR: git executable not found on PATH.", C.RED)
        return 2

    if args.repo:
        repo = Path(args.repo).expanduser()
        try:
            repo = repo.resolve()
        except OSError:
            pass
        if not repo.exists():
            warn(f"ERROR: {repo} does not exist.", C.RED)
            return 2
        if not repo.is_dir():
            warn(f"ERROR: {repo} is not a directory.", C.RED)
            return 2
        if not looks_like_git_repo(repo):
            warn(
                f"ERROR: {repo} does not look like a git repository "
                "(no .git entry, and not a bare repo).",
                C.RED,
            )
            return 2
    else:
        found = find_repo_root(Path.cwd())
        if found is None:
            warn(
                "ERROR: not inside a git repository (use -C DIR to point at one).",
                C.RED,
            )
            return 2
        repo = found

    options = CollectOptions(
        repo=repo,
        ref=args.ref or "HEAD",
        since=args.since,
        until=args.until,
        paths=tuple(args.path),
        author=args.author,
        exclude_author=args.exclude_author,
        no_merges=not args.merges,
        use_mailmap=args.use_mailmap,
        author_key=args.by,
        use_commit_date=(args.date == "commit"),
        utc=args.utc,
    )

    try:
        report = collect(options)
    except KeyboardInterrupt:
        warn("\nAborted by user.", C.YELLOW)
        return 130
    except GitError as exc:
        message = str(exc)
        lowered = message.lower()
        if "does not have any commits" in lowered:
            warn("This repository has no commits yet.", C.YELLOW)
            return 1
        if "unknown revision" in lowered or "bad revision" in lowered:
            warn(f"ERROR: unknown ref '{options.ref}'.", C.RED)
            return 2
        warn(f"ERROR: {message}", C.RED)
        return 2

    if report.commits == 0:
        warn("No commits matched the given filters.", C.YELLOW)

    all_authors = report.authors
    total_commits = sum(author.commits for author in all_authors)

    sorted_authors = sort_authors(all_authors, args.sort, args.reverse)
    shown = [
        author
        for author in sorted_authors
        if author.commits >= max(1, args.min_commits)
    ]
    if args.top and args.top > 0:
        shown = shown[: args.top]

    fields = resolve_fields(args.fields, CSV_FIELDS)

    # ---- stdout output ----------------------------------------------------
    if args.json or args.jsonl:
        records = [
            {
                key: value
                for key, value in author_record(
                    author, total_commits, options.utc
                ).items()
                if key in fields
            }
            for author in shown
        ]

        if args.json:
            payload: Dict[str, Any] = {
                "repository": str(report.repo),
                "ref": options.ref,
                "summary": build_summary(report, options),
                "authors": records,
            }
            if args.activity:
                buckets = activity(report.timestamps, args.activity, options.utc)
                payload["activity"] = {
                    "period": args.activity,
                    "buckets": [
                        {"period": label, "commits": count} for label, count in buckets
                    ],
                }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            for record in records:
                print(json.dumps(record, ensure_ascii=False))
    else:
        render_human(report, options, args, shown, total_commits)

    # ---- CSV output -------------------------------------------------------
    if args.csv:
        rows = [author_record(author, total_commits, options.utc) for author in shown]
        try:
            write_csv(args.csv, rows, fields, args.no_header)
        except OSError as exc:
            warn(f"ERROR: cannot write {args.csv}: {exc}", C.RED)
            return 2
        if not args.quiet:
            warn(f"CSV written to: {args.csv}", C.GREEN)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        warn("\nAborted by user.")
        sys.exit(130)
