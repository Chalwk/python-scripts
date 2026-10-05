---
layout: page
title: Contributing
subtitle: Bugs, ideas, and pull requests are welcome.
permalink: /contributing/
---

## Reporting a bug

Use the [bug report template](https://github.com/{{ site.repository }}/issues/new?template=bug-report.yaml)
and include:

- Which script is misbehaving
- The exact command you ran
- The full traceback or error output
- Your Python version and OS

**Redact any API keys, tokens, or real IP addresses before posting.**

## Reporting a security issue

**Do not open a public issue for security problems.**

Use the private [Report a vulnerability](https://github.com/{{ site.repository }}/security/advisories/new)
flow on the Security tab, or see [SECURITY.md](https://github.com/{{ site.repository }}/blob/main/SECURITY.md)
for the full policy, scope, and expected timelines.

## Suggesting a script or feature

Use the [script request template](https://github.com/{{ site.repository }}/issues/new?template=script-request.yaml).
Describe the problem you're trying to solve, not the solution you have in
mind - that gives me more room to suggest something simpler than what you'd
expect.

## Pull requests

Before opening a PR, make sure:

- The script runs cleanly on Python 3.8+
- Standard library only, or new dependencies are listed at the top of the
  script *and* in the README
- `--help` output is up to date
- No hardcoded secrets, API keys, or real IP addresses
- You've tested the cases described in the related issue

See [`.github/pull_request_template.md`](https://github.com/{{ site.repository }}/blob/main/.github/pull_request_template.md)
for the full checklist.

## Code style

There's no enforced linter, but the house style is:

- 4-space indentation, 88-column soft limit
- Type hints on function signatures where they help
- Docstrings on modules and non-obvious functions
- Standard library preferred over third-party packages

## Questions

Open a [GitHub Discussion](https://github.com/{{ site.repository }}/discussions)
or find me on [Discord](https://discord.gg/wuVcM9AZrr).