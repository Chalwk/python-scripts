---
title: ipqs_lookup.py
source_path: netsec/ipqs_lookup.py
category: Network & Security
description: "IPQualityScore proxy / VPN / Tor / fraud lookup with a transparent two-layer verdict."
tags: [security, networking, api, cli]
features:
  - "Two-layer verdict (IPQS score + local evidence score)"
  - "JSON, JSONL, CSV and compact TSV output"
  - "On-disk cache with PII-aware redaction"
  - "`--self-test` runs offline, no API key needed"
---

Look up IP addresses against the
[IPQualityScore](https://www.ipqualityscore.com/) Proxy & VPN Detection API
and get back a transparent, two-layer verdict instead of a single unexplained
number.

```
================================================================================
IP: 45.159.90.222   VERDICT: SUSPICIOUS   RISK: 81/100
IPQS: SUSPICIOUS   EVIDENCE: 86/100
TAGS: [ACTIVE-VPN] [PROXY] [DATACENTER]
================================================================================
```

The IPQS API returns a `fraud_score` and a pile of individual flags. The score
is authoritative but opaque; the flags are informative but scattered. This
script gives you both:

1. **IPQS Fraud Score classification** - the official number, mapped onto
   IPQS's own documented bands (`>=75` suspicious, `>=85` high risk,
   `>=90` recommended block).
2. **Local evidence score** - a transparent, weighted score computed from the
   individual flags (`active_vpn`, `recent_abuse`, `abuse_velocity`,
   `high_risk_attacks`, and so on).

The local score is **never presented as IPQS's own score**. The final verdict
is the higher of the two, so local evidence can elevate a verdict but never
suppress a bad IPQS score. Every point contribution is printed in a
`WHY THIS TOOL VERDICT` section, so you can disagree with the weighting and
change it in `CONFIG["local_weights"]`.

## Quick start

```bash
export IPQS_API_KEY="your_key_here"      # Linux / macOS
setx IPQS_API_KEY "your_key_here"        # Windows

python netsec/ipqs_lookup.py 8.8.8.8
python netsec/ipqs_lookup.py --file ips.txt --only-flagged
python netsec/ipqs_lookup.py --file ips.txt --report
python netsec/ipqs_lookup.py --self-test
```

Get a free key (1,000 lookups) at
[ipqualityscore.com](https://www.ipqualityscore.com/).

## Full options

```bash
python netsec/ipqs_lookup.py --help
```

Highlights:

| Flag                       | Purpose                                          |
| -------------------------- | ------------------------------------------------ |
| `--json` / `--jsonl`       | Machine-readable output                          |
| `--csv PATH`               | Write CSV                                        |
| `--report`                 | Prioritised risk report instead of summary table |
| `--only-flagged`           | Hide CLEAN results                               |
| `--redact`                 | Strip PII from every output mode                 |
| `--fields a,b,c`           | Narrow CSV/JSON export                           |
| `--strictness 0-3`         | IPQS strictness (default `0`)                    |
| `--workers N` / `--rps N`  | Parallelism and rate limiting                    |
| `--refresh` / `--no-cache` | Cache control                                    |
| `--config FILE`            | JSON config overrides                            |

## Notes

- API key sent in the `IPQS-KEY` header by default, never in the URL.
- Responses cached for 6 hours on disk so repeat runs don't burn credits.
- Requests containing PII are **not** cached unless you pass `--cache-sensitive`.
- Enterprise fields (`frequent_abuser`, `high_risk_attacks`, `trusted_network`)
  and premium fields (`reasons`) are absent on lower plans; the script notes
  which ones weren't returned rather than silently scoring around them.