---
title: git_stats.py
source_path: src/automation/git_stats.py
category: Automation
description: "Per-author commit statistics, bus-factor estimate and activity histogram from `git log`."
tags: [git, cli, reporting]
features:
  - "Per-author commits, churn, active days and share of total"
  - "Bus-factor estimate at 50% and 80% coverage"
  - "Optional day / week / month / year activity histogram with sparkline"
  - "JSON, JSONL and CSV output"
  - "`--self-test` runs offline, no repo or API key needed"
---

Per-author commit statistics from `git log --numstat`, with a bus-factor
estimate and an optional commit histogram by day, week, month or year.

```
================================================================================
REPOSITORY  /home/chalwk/code/python-scripts
REF         main
DATES       author date, local time
================================================================================

OVERVIEW
  Commits                    184
  Contributors                 3
  Files changed              412
  Insertions            + 12,904
  Deletions             -  3,118
  Net                   +  9,786
  First commit        2024-08-11
  Last commit         2026-04-02

BUS FACTOR
  Top 1 author   cover  78.3% of commits  (>= 50%)
  Top 2 authors  cover  94.6% of commits  (>= 80%)
  Risk: HIGH - a single contributor dominates this repository.

CONTRIBUTORS (by commits)
  #  AUTHOR                            COMMITS  SHARE    +LINES    -LINES      NET  ACTIVE  LAST
  1  Jericho Crosby <chalwk@…>             144  78.3%    11,204     2,101   +9,103     122  2026-04-02
  2  dependabot[bot] <49699333+…>           28  15.2%       900       517     +383      28  2026-03-19
  3  someone <someone@example.com>          12   6.5%       800       500     +300      12  2026-01-04
```

## Which repository

By default the script runs against the repo that encloses the current
directory - it walks upward until it finds a `.git` entry, exactly like
`git status`. That means it works from anywhere inside a working tree,
including deep subdirectories:

```bash
cd ~/code/python-scripts/src/automation
python ../git_stats.py            # audits the python-scripts repo
```

To point at a different repo, use `-C DIR` (or its long form, `--repo DIR`).
`~` is expanded and relative paths are resolved from your current directory:

```bash
python src/automation/git_stats.py -C ~/code/python-scripts
python src/automation/git_stats.py --repo /home/chalwk/code/some-project
```

Bare repositories are supported, but only via `-C` - the upward walk never
matches one, because there is no `.git` entry to find:

```bash
python src/automation/git_stats.py -C /srv/git/python-scripts.git
```

If the script can't find a repo, it exits with code `2` and a message that
says which of the two cases applied:

```
ERROR: not inside a git repository (use -C DIR to point at one).
ERROR: /tmp does not look like a git repository (no .git entry, and not a bare repo).
```

## Quick start

```bash
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
```

## Full options

```bash
python src/automation/git_stats.py --help
```

Highlights:

| Flag                                | Purpose                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------- |
| `-C DIR` / `--repo DIR`             | Point at a repo (worktree or bare) instead of searching upward from cwd |
| `--since` / `--until`               | Date range (git date syntax)                                            |
| `--path PATH`                       | Limit to a subdirectory, repeatable                                     |
| `--author` / `--exclude-author`     | Filter contributors by pattern                                          |
| `--merges`                          | Include merge commits (excluded by default)                             |
| `--by email\|name\|name+email`      | How contributors are grouped                                            |
| `--use-mailmap`                     | Honour `.mailmap`                                                       |
| `--sort` / `--reverse` / `--top`    | Ordering and trimming of the table                                      |
| `--activity day\|week\|month\|year` | Commit histogram with a sparkline                                       |
| `--json` / `--jsonl` / `--csv`      | Machine-readable output                                                 |
| `--fields a,b,c`                    | Narrow CSV/JSON export                                                  |

## Notes

- Merge commits are excluded by default because they double-count churn that
  already appears on the merged branch. Pass `--merges` to include them.
- `--since` / `--until` are evaluated by git against the **commit** date.
  Use `--date author|commit` to control which date is *displayed* and used
  for activity bucketing.
- Bus factor is the minimum number of top authors whose commits cover 50%
  and 80% of the total. A single author covering half the repo is flagged
  as high risk, which is honest rather than flattering.
- Author identity is grouped by lowercased email by default. Add a
  `.mailmap` and pass `--use-mailmap` if you have the same person under
  multiple addresses.
- Bare repositories are only discoverable via `-C`; the upward walk matches
  worktrees only, mirroring git's own behaviour.
- The script shells out to `git` and never touches the network.

---