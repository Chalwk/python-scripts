# python-scripts

[![Website](https://img.shields.io/badge/website-chalwk.github.io%2Fpython--scripts-blue)](https://chalwk.github.io/python-scripts/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Assorted self-contained Python scripts.

Full documentation for each script lives on the [website](https://chalwk.github.io/python-scripts/).

---

## Index

### Network & security

| Script                                           | Docs                                                                          | What it does                                                                         |
| ------------------------------------------------ | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| [`netsec/ipqs_lookup.py`](netsec/ipqs_lookup.py) | [Read the docs](https://chalwk.github.io/python-scripts/scripts/ipqs-lookup/) | IPQualityScore proxy / VPN / Tor / fraud lookup with a transparent two-layer verdict |

### Automation

*Nothing yet.*

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
python netsec/ipqs_lookup.py --help
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

## License

MIT - see [LICENSE](LICENSE).

Copyright (c) 2026 Jericho Crosby (Chalwk)