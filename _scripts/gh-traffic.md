---
title: gh-traffic.py
source_path: src/automation/gh-traffic.py
category: Automation
description: "GitHub repository traffic statistics: clones, views, referrers, popular paths, releases and metadata."
tags: [github, api, cli, reporting, traffic]
latest_version: 1.0
features:
  - "Clones and views (totals, uniques, and per-day breakdown)"
  - "Top referring sites and popular content paths"
  - "Repository metadata: stars, forks, watchers, issues, size, language"
  - "Release counts and download totals (per-release and latest)"
  - "Auto-discovery of repositories owned by a user or org"
  - "Spike detection on the 14-day window (z-score)"
  - "Clone-to-view ratio and a likely-bot-traffic heuristic"
  - "Optional JSON archive that outlives GitHub's 14-day retention"
  - "TTL cache so repeat runs don't burn API calls"
  - "JSON, JSONL, and CSV output"
  - "`--self-test` runs offline, no token needed"
---

Pull traffic statistics for one or more GitHub repositories. The GitHub
traffic API only retains 14 days of data, so the script can also archive
every response it fetches to a local JSON file per repository, letting you
build a permanent history that outlives that window.

```
================================================================================
REPOSITORY  your-username/your-repo-name
FETCHED     2026-10-11T22:00:43.320688+00:00
================================================================================

REPOSITORY INFO
  Stars: 1   Forks: 0   Watchers: 1            Subscribers: 1   Open issues: 0
  Language: Python      License: MIT           Size: 109 KB
  Created: 2026-10-04   Updated: 2026-10-08    Pushed: 2026-10-08
  Releases: 3           Total downloads: 190   Latest: v1.2.0 (42 downloads)

CLONES (last 14 days)
  Total: 80   Unique cloners: 37

  DATE           COUNT  UNIQUE
  2026-10-04        10       6
  2026-10-05        51      24
  2026-10-06         8       3
  ...

VIEWS (last 14 days)
  Total: 126   Unique visitors: 3

REFERRING SITES (2)
  SITE                   VIEWS  UNIQUE
  google.com                 3       1
  github.com                 3       1

POPULAR CONTENT (10)
  CONTENT                                        VIEWS  UNIQUE
  /owner/repo                                       34       2
  /owner/repo/discussions/categories                10       1
  ...

ACTIVITY ANALYSIS
  Clone/view ratio: 0.63
  Peak clone day:   2026-10-05 (51 clones, 24 uniques)
  Peak view day:    2026-10-05 (64 views, 2 uniques)
  Clone spikes:
    2026-10-05      51  (z=3.48)
  View spikes:
    2026-10-05      64  (z=3.0)
```

A summary table is printed at the end when more than one repository is
fetched:

```
SUMMARY
============================================================================================================================
REPOSITORY                           CLONES   UNIQUE    VIEWS   UNIQUE   RATIO   STARS   FORKS  ISSUES        DL   REF  PATH
----------------------------------------------------------------------------------------------------------------------------
owner/repo-a                            605      220      285        7    2.12       1       0       0         0     1    10
owner/repo-b                            229      107      315       37    0.73      38      11       0       190     5    10
```

## Setup

The traffic endpoints require **push (write) access** to the repository.
Fine-grained tokens need the *Administration* repository permission
(**read**) on each repo you want to audit.

```bash
export GITHUB_TOKEN="ghp_..."       # Linux / macOS
setx GITHUB_TOKEN "ghp_..."         # Windows
```

`GH_TOKEN` and `GITHUB_ACCESS_TOKEN` are also checked, in that order.

## Quick start

```bash
python src/automation/gh-traffic.py --repo owner/name
python src/automation/gh-traffic.py --repo owner/name --repo owner/other
python src/automation/gh-traffic.py --file repos.txt
python src/automation/gh-traffic.py --discover your-username
python src/automation/gh-traffic.py --file repos.txt --json > traffic.json
python src/automation/gh-traffic.py --file repos.txt --csv traffic.csv
python src/automation/gh-traffic.py --repo owner/name --archive ~/.gh-traffic
python src/automation/gh-traffic.py --repo owner/name --history
python src/automation/gh-traffic.py --repo owner/name --cache-ttl 3600
python src/automation/gh-traffic.py --repo owner/name --refresh
python src/automation/gh-traffic.py --self-test
```

`--file` accepts one repo per line, `#` comments, and comma/semicolon/space
separators. `--discover` calls `/users/{owner}/repos` and, by default, skips
forks and archived repos (use `--include-forks` / `--include-archived` to
keep them).

## Full options

```bash
python src/automation/gh-traffic.py --help
```

Highlights:

| Flag                  | Purpose                                                    |
| --------------------- | ---------------------------------------------------------- |
| `--repo OWNER/NAME`   | Repository to check. Repeatable.                           |
| `--file PATH`         | Read the repository list from a file.                      |
| `--discover OWNER`    | Auto-discover repos owned by a user or org.                |
| `--list-repos`        | List repositories in the archive and exit.                 |
| `--json` / `--jsonl`  | Machine-readable output.                                   |
| `--csv PATH`          | Summary CSV, one row per repository.                       |
| `--csv-daily PATH`    | Daily clones/views CSV, one row per day per repo.          |
| `--archive DIR`       | Archive directory (default: `~/.cache/gh-traffic`).        |
| `--history`           | Show archived history instead of fetching.                 |
| `--cache-ttl SECONDS` | Reuse cached data if younger than this.                    |
| `--refresh`           | Ignore the cache and always fetch fresh data.              |
| `--no-repo-stats`     | Skip metadata (stars/forks/issues/releases) to save calls. |
| `--workers N`         | Parallel lookups (default: 4).                             |
| `--redact`            | Redact repo names and paths in the output.                 |

## Notes

- **Push access required.** A 403 on a repo means the token doesn't have
  write access to it, not that the token is invalid.
- **14-day retention is real.** GitHub discards traffic data older than 14
  days and offers no backfill. The archive is the only way to keep it. Run
  the script on a schedule if you care about long-term history.
- **The "likely bot traffic" heuristic is worth trusting.** A repo with
  hundreds of clones and single-digit unique viewers is being scraped,
  mirrored, or crawled - not read. The summary table's clone columns are
  dominated by this on most accounts.
- **Clone and view counts are rolling.** Each fetch is the *current*
  14-day window, not an increment. The archive's per-day map keeps the
  highest count seen for each date, which is the right behaviour when
  windows overlap but wrong if GitHub ever revises a day downward.
- **Stats history is capped at 365 entries.** Per-day clone/view history
  is kept forever in the archive, but the metadata timeline
  (`stats_history`) keeps the last year only.
- **`--history` reads the archive and never hits the network.** Useful for
  looking at old data after the token has expired.
- **The cache and the archive are separate.** `--cache-ttl` short-circuits
  *fetches*; the archive is written regardless. `--refresh` bypasses the
  cache but still updates the archive.
- No third-party packages. Standard library only.