# python-scripts

[![Website](https://img.shields.io/badge/website-chalwk.github.io%2Fpython--scripts-blue)](https://chalwk.github.io/python-scripts/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Assorted self-contained Python scripts.

Full documentation for each script lives on the [website](https://chalwk.github.io/python-scripts/).

---

## Index

### Network & security

| Script                                                   | Docs                                                                          | What it does                                                                         |
| -------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| [`src/netsec/ipqs_lookup.py`](src/netsec/ipqs_lookup.py) | [Read the docs](https://chalwk.github.io/python-scripts/scripts/ipqs-lookup/) | IPQualityScore proxy / VPN / Tor / fraud lookup with a transparent two-layer verdict |

### Automation

| Script                                                               | Docs                                                                            | What it does                                                                      |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| [`src/automation/git_stats.py`](src/automation/git_stats.py)         | [Read the docs](https://chalwk.github.io/python-scripts/scripts/git-stats/)     | Per-author commit stats, bus-factor estimate, and commit histogram from `git log` |
| [`src/automation/discord_audit.py`](src/automation/discord_audit.py) | [Read the docs](https://chalwk.github.io/python-scripts/scripts/discord-audit/) | Read-only Discord guild audit: channels, permission overwrites, roles and members |

### Text & data

*Nothing yet.*

### Web

*Nothing yet.*

### Misc

*Nothing yet.*

---

## Requirements

- Python 3.8 or newer
- Standard library only unless a script says otherwise at the top
- Per-script API keys where noted

Clone and run:

```bash
git clone https://github.com/Chalwk/python-scripts.git
cd python-scripts
python src/netsec/ipqs_lookup.py --help
```

---

## Conventions

Scripts in this repo try to follow a few house rules:

- **Python 3.8+**, standard library preferred. If a third-party package is
  genuinely required, it's listed at the top of the script and in the index.
- **`--help` works.** Every script has a real argument parser, not positional
  guesswork.
- **`--self-test` where it makes sense.** Offline tests, no API key, no network.
- **Secrets come from the environment first**, command line second, config file
  third, hardcoded last (and never hardcoded in a published script).
- **Destructive actions are opt-in**, not default.
- **MIT licensed.** Take what's useful.

---

## Layout

```
src/                Python source (excluded from the Jekyll build)
├── netsec/         Network & security
├── automation/     Automation & reporting
├── text/           Text & data
├── web/            Web
└── misc/           Everything else

_scripts/           Jekyll collection: one doc page per script
```

---

## License

MIT - see [LICENSE](LICENSE).

Copyright (c) 2026 Jericho Crosby (Chalwk)