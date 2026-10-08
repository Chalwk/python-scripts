---
title: discord_audit.py
source_path: src/automation/discord_audit.py
category: Automation
description: "Read-only Discord guild audit: channels, permission overwrites, roles and members."
tags: [discord, api, cli, audit]
features:
  - "Channels grouped by category, with every permission overwrite spelled out"
  - "Roles sorted by position, with per-role member counts and elevated-permission flags"
  - "`--members` lists every member and their roles (requires Server Members Intent)"
  - "`--as-user` computes a real per-channel effective-permission view for one user"
  - "JSON, JSONL, CSV output and `--redact` for stable ID hashing"
  - "`--self-test` runs offline, no token needed"
---

Dump everything about a Discord guild you own: channels, their permission
overwrites, roles, and (optionally) the member list. Read-only - the script
only issues `GET` requests to the Discord REST API v10.

```
================================================================================
GUILD      My Server  (123456789012345678)
MEMBERS    342 (approx.)
================================================================================

ROLES (12)
   POS  NAME              COLOR     HOIST  MENTION   MEMBERS  PERMISSIONS
    11  @Admin            #ED4245   yes    yes             3  ADMINISTRATOR (all permissions)
    10  @Moderators       #5865F2   yes    yes            14  18 perm(s)  [elevated]
     0  @everyone         -         no     no            342  8 perm(s)

CHANNELS (27)
  📁 Info  [category]
    # rules
       overwrites:
         - @everyone  deny: SEND_MESSAGES
         - @Moderators  allow: SEND_MESSAGES
    # announcements
       overwrites:
         - @everyone  deny: SEND_MESSAGES
  📁 Voice  [category]
    🔊 General
    🔊 AFK

MEMBERS (342)
  NAME              NICK          ID                    JOINED      ROLES
  alice             alice         123456789012345678    2024-01-15  @Moderators, @everyone
  bob               bobby         987654321098765432    2024-03-22  @everyone [bot]
```

The `[elevated]` marker on a role means it holds a permission from the
"Dangerous" set (`MANAGE_GUILD`, `MANAGE_ROLES`, `BAN_MEMBERS`, `MENTION_EVERYONE`,
and so on). `ADMINISTRATOR` gets its own callout because it silently grants
everything - including bypassing channel overwrites that would otherwise deny
the role.

## Setup

This script uses a **bot token**, not a user token. A user token
(self-botting) violates Discord's Terms of Service and can get your account
banned; the script sends `Authorization: Bot <token>`, so a user token will
simply be rejected by the API.

1. Create a bot at
   [discord.com/developers/applications](https://discord.com/developers/applications).
2. **Bot → Privileged Gateway Intents → enable "Server Members Intent".**
   Required for `--members`. Without it, the members endpoint returns `403`.
3. **OAuth2 → URL Generator** → scope `bot`, permission `View Channels` →
   open the URL → pick your server → Authorize.
4. Set the token:

```bash
export DISCORD_AUDIT_BOT_TOKEN="your_token_here"      # Linux / macOS
setx DISCORD_AUDIT_BOT_TOKEN "your_token_here"        # Windows
```

## Quick start

```bash
python src/automation/discord_audit.py                          # roles + channels
python src/automation/discord_audit.py --members                # + member list
python src/automation/discord_audit.py --members --role Moderators
python src/automation/discord_audit.py --as-user 123456789012345678
python src/automation/discord_audit.py --json > audit.json
python src/automation/discord_audit.py --self-test
```

## Full options

```bash
python src/automation/discord_audit.py --help
```

Highlights:

| Flag                  | Purpose                                                   |
| --------------------- | --------------------------------------------------------- |
| `--guild ID`          | Target a specific guild (needed if the bot is in several) |
| `--list-guilds`       | Show which guilds the bot can see, then exit              |
| `--members`           | Fetch and list members (requires Server Members Intent)   |
| `--role NAME_OR_ID`   | Filter to members with a given role (implies `--members`) |
| `--include-bots`      | Include bot accounts in the member list                   |
| `--as-user USER_ID`   | Per-channel effective permissions for one user            |
| `--json` / `--jsonl`  | Machine-readable output                                   |
| `--csv-members PATH`  | Write the member table to CSV                             |
| `--csv-channels PATH` | Write the channel table to CSV                            |
| `--redact`            | Hash user and role IDs (stable, non-reversible)           |

## Notes

- **Read-only.** Nothing in this script issues `POST`, `PATCH`, or `DELETE`.
  If you're looking for a tool that changes permissions, this isn't it.
- **`--as-user` implements the real permission algorithm.** It follows
  Discord's documented order: OR every role → short-circuit on
  `ADMINISTRATOR` → apply `@everyone` overwrite → apply the union of role
  overwrites → apply the member overwrite. Each step applies deny before
  allow, exactly as Discord does.
- **Rate limits are handled properly.** `429` responses read the
  `retry_after` value and honour the `global` flag; `5xx` gets exponential
  backoff with jitter; `401`, `403`, and `404` fail fast rather than burning
  retries.
- **`--redact` hashes IDs with a fixed salt**, so the same user is
  consistently `id-abc123...` across a single run. Useful for sharing audit
  output without leaking IDs, and the mapping is not reversible.
- **Threads are not listed.** The guild channels endpoint only returns
  parent channels; threads inherit permissions from their parent, so
  `--as-user` reports on the parent and the answer is the same.
- No third-party packages. Standard library only.

---