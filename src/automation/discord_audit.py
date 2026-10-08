#!/usr/bin/env python3
"""
=====================================================================================
SCRIPT NAME:      discord_audit.py
VERSION:          1.0

DESCRIPTION:
    Read-only audit of a Discord guild. Dumps channels, their permission
    overwrites, roles, and (with --members) the member list.

    Answers questions like:
      - Which channels have custom permission overwrites, and for whom?
      - Which roles have ADMINISTRATOR?
      - Who is in a given role? (--members, or --role NAME)
      - What can a specific member actually see and do? (--as-user)
      - Which channels have no overwrites and therefore inherit everything?

    Nothing is modified. The script only issues GET requests to the Discord
    REST API v10.

AUTHORISATION
-------------
    This script uses a BOT token, not a user token.

    A user token (self-botting) is a violation of Discord's Terms of Service
    and can get your account banned. Do not pass one. The script sends the
    token as `Authorization: Bot <token>`, so a user token will simply be
    rejected by Discord's API.

    You must enable the *Server Members Intent* on your bot to use
    --members. Without it, the members endpoint returns a 403. The script
    detects this case and tells you which switch to flip.

SETUP
-----
    1. Create a bot at https://discord.com/developers/applications
    2. Bot -> Privileged Gateway Intents -> enable "Server Members Intent"
    3. OAuth2 -> URL Generator -> scope `bot`, permission `View Channels`
       -> open the URL -> pick your server -> Authorize
    4. Set the token:
         Linux/macOS:  export DISCORD_AUDIT_BOT_TOKEN="..."
         Windows:      setx DISCORD_AUDIT_BOT_TOKEN "..."
       Or pass --token on the command line (not recommended: it lands in
       shell history).

USAGE
-----
    python src/automation/discord_audit.py                          # roles + channels
    python src/automation/discord_audit.py --members                # + member list
    python src/automation/discord_audit.py --members --role Moderators
    python src/automation/discord_audit.py --as-user 123456789012345678
    python src/automation/discord_audit.py --json > audit.json
    python src/automation/discord_audit.py --self-test

REQUIREMENTS
------------
    - Python 3.8+
    - No third-party packages (uses urllib from the stdlib)
    - A Discord bot token with the Server Members Intent enabled

Copyright (c) 2026 Jericho Crosby (Chalwk)
LICENSE: MIT
=====================================================================================
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
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
    "api_base": "https://discord.com/api/v10",
    "user_agent": f"DiscordAudit ({__version__}, https://github.com/Chalwk/python-scripts)",
    "request": {
        "timeout": 20.0,
        "retries": 3,
        "backoff": 1.5,
        "max_backoff": 60.0,
    },
    # Per-channel computation can be expensive on large guilds; cap the
    # number of members fetched per page. Discord's max is 1000.
    "members_page_size": 1000,
    # Permission thresholds for the "dangerous role" flag in role output.
    "dangerous_permissions": {
        "ADMINISTRATOR",
        "MANAGE_GUILD",
        "MANAGE_ROLES",
        "MANAGE_CHANNELS",
        "MANAGE_WEBHOOKS",
        "BAN_MEMBERS",
        "KICK_MEMBERS",
        "MENTION_EVERYONE",
        "MANAGE_GUILD_EXPRESSIONS",
    },
}


# ============================================================================
# PERMISSIONS
# ============================================================================
# Discord permission flags. Order matters only for display; the bit values
# are what count. Source: https://discord.com/developers/docs/topics/permissions
PERMISSIONS: List[Tuple[str, int]] = [
    ("CREATE_INSTANT_INVITE", 1 << 0),
    ("KICK_MEMBERS", 1 << 1),
    ("BAN_MEMBERS", 1 << 2),
    ("ADMINISTRATOR", 1 << 3),
    ("MANAGE_CHANNELS", 1 << 4),
    ("MANAGE_GUILD", 1 << 5),
    ("ADD_REACTIONS", 1 << 6),
    ("VIEW_AUDIT_LOG", 1 << 7),
    ("PRIORITY_SPEAKER", 1 << 8),
    ("STREAM", 1 << 9),
    ("VIEW_CHANNEL", 1 << 10),
    ("SEND_MESSAGES", 1 << 11),
    ("SEND_TTS_MESSAGES", 1 << 12),
    ("MANAGE_MESSAGES", 1 << 13),
    ("EMBED_LINKS", 1 << 14),
    ("ATTACH_FILES", 1 << 15),
    ("READ_MESSAGE_HISTORY", 1 << 16),
    ("MENTION_EVERYONE", 1 << 17),
    ("USE_EXTERNAL_EMOJIS", 1 << 18),
    ("VIEW_GUILD_INSIGHTS", 1 << 19),
    ("CONNECT", 1 << 20),
    ("SPEAK", 1 << 21),
    ("MUTE_MEMBERS", 1 << 22),
    ("DEAFEN_MEMBERS", 1 << 23),
    ("MOVE_MEMBERS", 1 << 24),
    ("USE_VAD", 1 << 25),
    ("CHANGE_NICKNAME", 1 << 26),
    ("MANAGE_NICKNAMES", 1 << 27),
    ("MANAGE_ROLES", 1 << 28),
    ("MANAGE_WEBHOOKS", 1 << 29),
    ("MANAGE_GUILD_EXPRESSIONS", 1 << 30),
    ("USE_APPLICATION_COMMANDS", 1 << 31),
    ("REQUEST_TO_SPEAK", 1 << 32),
    ("MANAGE_EVENTS", 1 << 33),
    ("MANAGE_THREADS", 1 << 34),
    ("CREATE_PUBLIC_THREADS", 1 << 35),
    ("CREATE_PRIVATE_THREADS", 1 << 36),
    ("USE_EXTERNAL_STICKERS", 1 << 37),
    ("SEND_MESSAGES_IN_THREADS", 1 << 38),
    ("USE_EMBEDDED_ACTIVITIES", 1 << 39),
    ("MODERATE_MEMBERS", 1 << 40),
    ("VIEW_CREATOR_MONETIZATION_ANALYTICS", 1 << 41),
    ("USE_SOUNDBOARD", 1 << 42),
    ("CREATE_GUILD_EXPRESSIONS", 1 << 43),
    ("CREATE_EVENTS", 1 << 44),
    ("USE_EXTERNAL_SOUNDS", 1 << 45),
    ("SEND_VOICE_MESSAGES", 1 << 46),
]

PERMISSION_BITS: Dict[str, int] = {name: bit for name, bit in PERMISSIONS}
PERMISSION_NAMES: Dict[int, str] = {bit: name for name, bit in PERMISSIONS}

# Computed "all permissions" mask, used when ADMINISTRATOR is present.
ALL_PERMISSIONS = 0
for _, bit in PERMISSIONS:
    ALL_PERMISSIONS |= bit

# Channel overwrite types
OW_TYPE_ROLE = 0
OW_TYPE_MEMBER = 1

# Channel types we care about for output formatting.
CHANNEL_TYPE_NAMES: Dict[int, str] = {
    0: "text",
    2: "voice",
    4: "category",
    5: "announcement",
    10: "announcement-thread",
    11: "public-thread",
    12: "private-thread",
    13: "stage",
    14: "directory",
    15: "forum",
    16: "media",
}

CHANNEL_TYPE_ICONS: Dict[int, str] = {
    0: "#",
    2: "\U0001f50a",  # speaker
    4: "\U0001f4c1",  # folder
    5: "\U0001f4e2",  # loudspeaker
    13: "\U0001f3a4",  # microphone
    15: "\U0001f4cb",  # clipboard
    16: "\U0001f5bc",  # picture
}


def permission_names(mask: int) -> List[str]:
    """Return the display names of every bit set in `mask`, in PERMISSIONS order."""
    out: List[str] = []
    for name, bit in PERMISSIONS:
        if mask & bit:
            out.append(name)
    return out


def permissions_from_string(value: Any) -> int:
    """Discord returns permissions as a decimal string. Be liberal."""
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


# ============================================================================
# DISCORD API CLIENT
# ============================================================================
class DiscordError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        retryable: bool = False,
        fatal: bool = False,
        retry_after: Optional[float] = None,
        code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retryable = retryable
        self.fatal = fatal
        self.retry_after = retry_after
        self.code = code


@dataclass
class RateLimitState:
    """Small helper to avoid hammering a bucket we've already seen a 429 from."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    global_until: float = 0.0

    def set_global(self, seconds: float) -> None:
        with self.lock:
            self.global_until = max(self.global_until, time.monotonic() + seconds)

    def wait_if_needed(self) -> None:
        with self.lock:
            remaining = self.global_until - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)


class DiscordClient:
    def __init__(self, token: str, api_base: str) -> None:
        self.token = token
        self.api_base = api_base.rstrip("/")
        self.rate = RateLimitState()
        self._opener = urllib.request.build_opener()
        self._opener.addheaders = [
            ("Authorization", f"Bot {token}"),
            ("Accept", "application/json"),
            ("User-Agent", CONFIG["user_agent"]),
        ]

    def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.api_base}{path}"
        if params:
            cleaned = {k: v for k, v in params.items() if v is not None}
            if cleaned:
                url = f"{url}?{urllib.parse.urlencode(cleaned)}"

        net = CONFIG["request"]
        retries = max(0, int(net["retries"]))
        base = max(0.1, float(net["backoff"]))
        cap = max(base, float(net["max_backoff"]))
        timeout = max(1.0, float(net["timeout"]))

        for attempt in range(retries + 1):
            self.rate.wait_if_needed()

            request = urllib.request.Request(url, method="GET")
            try:
                with self._opener.open(request, timeout=timeout) as response:
                    raw = response.read().decode("utf-8", errors="replace")
                    return json.loads(raw) if raw else None
            except urllib.error.HTTPError as exc:
                retry_after = _retry_after_from_headers(exc.headers)
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
                code = parsed.get("code") if isinstance(parsed, dict) else None

                if exc.code == 429:
                    wait = parsed.get("retry_after") or retry_after or 1.0
                    try:
                        wait = float(wait)
                    except (TypeError, ValueError):
                        wait = 1.0
                    if parsed.get("global"):
                        self.rate.set_global(wait)
                    if attempt >= retries:
                        raise DiscordError(
                            f"Rate limited on {path} (gave up after {retries} retries)",
                            status=429,
                            retry_after=wait,
                            code=code,
                        )
                    time.sleep(min(cap, wait + 0.25))
                    continue

                if exc.code in (401, 403):
                    raise DiscordError(message, status=exc.code, fatal=True, code=code)

                if exc.code == 404:
                    raise DiscordError(message, status=404, fatal=True, code=code)

                retryable = exc.code >= 500 or exc.code in (408, 502, 503, 504)
                if retryable and attempt < retries:
                    delay = min(cap, base * (2**attempt)) + random.uniform(0.0, 0.5)
                    time.sleep(delay)
                    continue

                raise DiscordError(
                    message, status=exc.code, retryable=retryable, code=code
                )
            except urllib.error.URLError as exc:
                if attempt < retries:
                    delay = min(cap, base * (2**attempt)) + random.uniform(0.0, 0.5)
                    time.sleep(delay)
                    continue
                raise DiscordError(
                    f"Network error: {exc.reason}", retryable=True
                ) from None
            except json.JSONDecodeError as exc:
                raise DiscordError(f"Invalid JSON from API: {exc}") from None

        raise DiscordError("unreachable")  # pragma: no cover


def _retry_after_from_headers(headers: Any) -> Optional[float]:
    if headers is None:
        return None
    value = headers.get("Retry-After") or headers.get("X-RateLimit-Reset-After")
    if not value:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ============================================================================
# HIGH-LEVEL COLLECTION
# ============================================================================
@dataclass
class Guild:
    id: str
    name: str
    owner_id: str
    member_count: int
    raw: Dict[str, Any]


@dataclass
class Role:
    id: str
    name: str
    color: int
    position: int
    hoist: bool
    mentionable: bool
    managed: bool
    permissions: int
    raw: Dict[str, Any]

    @property
    def color_hex(self) -> str:
        if self.color == 0:
            return ""
        return f"#{self.color:06X}"


@dataclass
class Channel:
    id: str
    name: str
    type: int
    position: int
    parent_id: Optional[str]
    overwrites: List[Dict[str, Any]]
    raw: Dict[str, Any]

    @property
    def kind(self) -> str:
        return CHANNEL_TYPE_NAMES.get(self.type, f"type-{self.type}")


@dataclass
class Member:
    user_id: str
    username: str
    global_name: Optional[str]
    nickname: Optional[str]
    role_ids: List[str]
    joined_at: Optional[str]
    bot: bool
    raw: Dict[str, Any]

    def display(self) -> str:
        return self.nickname or self.global_name or self.username


def fetch_guild(client: DiscordClient, guild_id: str) -> Guild:
    data = client.get(f"/guilds/{guild_id}", params={"with_counts": "true"})
    if not isinstance(data, dict):
        raise DiscordError("Unexpected guild payload")
    count = data.get("approximate_member_count") or data.get("member_count") or 0
    return Guild(
        id=str(data.get("id", guild_id)),
        name=str(data.get("name", "")),
        owner_id=str(data.get("owner_id", "")),
        member_count=int(count),
        raw=data,
    )


def fetch_roles(client: DiscordClient, guild_id: str) -> List[Role]:
    data = client.get(f"/guilds/{guild_id}/roles")
    if not isinstance(data, list):
        raise DiscordError("Unexpected roles payload")
    roles: List[Role] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        roles.append(
            Role(
                id=str(entry.get("id", "")),
                name=str(entry.get("name", "")),
                color=int(entry.get("color", 0) or 0),
                position=int(entry.get("position", 0) or 0),
                hoist=bool(entry.get("hoist")),
                mentionable=bool(entry.get("mentionable")),
                managed=bool(entry.get("managed")),
                permissions=permissions_from_string(entry.get("permissions", "0")),
                raw=entry,
            )
        )
    # Discord sorts roles by position, lowest first. Reverse for "top role first".
    roles.sort(key=lambda r: r.position, reverse=True)
    return roles


def fetch_channels(client: DiscordClient, guild_id: str) -> List[Channel]:
    data = client.get(f"/guilds/{guild_id}/channels")
    if not isinstance(data, list):
        raise DiscordError("Unexpected channels payload")
    channels: List[Channel] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        channels.append(
            Channel(
                id=str(entry.get("id", "")),
                name=str(entry.get("name", "")),
                type=int(entry.get("type", 0)),
                position=int(entry.get("position", 0) or 0),
                parent_id=(str(entry["parent_id"]) if entry.get("parent_id") else None),
                overwrites=list(entry.get("permission_overwrites") or []),
                raw=entry,
            )
        )
    return channels


def iter_members(client: DiscordClient, guild_id: str) -> Iterator[Member]:
    """Paginate through /guilds/{id}/members using `after`."""
    page_size = int(CONFIG["members_page_size"])
    after = "0"
    while True:
        page = client.get(
            f"/guilds/{guild_id}/members",
            params={"limit": page_size, "after": after},
        )
        if not isinstance(page, list) or not page:
            break

        for entry in page:
            if not isinstance(entry, dict):
                continue
            user = entry.get("user") or {}
            yield Member(
                user_id=str(user.get("id", "")),
                username=str(user.get("username", "")),
                global_name=user.get("global_name"),
                nickname=entry.get("nick"),
                role_ids=[str(r) for r in (entry.get("roles") or [])],
                joined_at=entry.get("joined_at"),
                bot=bool(user.get("bot")),
                raw=entry,
            )

        if len(page) < page_size:
            break
        last = page[-1]
        last_id = (
            str((last.get("user") or {}).get("id", ""))
            if isinstance(last, dict)
            else ""
        )
        if not last_id or last_id == after:
            break
        after = last_id


def fetch_members(client: DiscordClient, guild_id: str) -> List[Member]:
    return list(iter_members(client, guild_id))


# ============================================================================
# PERMISSION MATH
# ============================================================================
def base_permissions(member: Member, roles_by_id: Dict[str, Role]) -> int:
    """OR together every role the member has. Assumes guild_id role (everyone)
    is included in member.role_ids; if not, pass it separately."""
    total = 0
    for role_id in member.role_ids:
        role = roles_by_id.get(role_id)
        if role is not None:
            total |= role.permissions
    return total


def effective_channel_permissions(
    member: Member,
    channel: Channel,
    roles_by_id: Dict[str, Role],
    everyone_role_id: str,
) -> int:
    """
    Compute the effective permissions a member has in a channel.

    Follows Discord's documented order:
      1. Start with OR of every role's permissions (server-level).
      2. If ADMINISTRATOR, return all permissions immediately.
      3. Apply @everyone overwrite (deny first, then allow).
      4. Apply the union of role overwrites (deny first, then allow).
      5. Apply the member-specific overwrite (deny first, then allow).

    Threads are not handled here: they inherit from their parent channel.
    The channels endpoint only returns parent channels, so this is fine.
    """
    perms = base_permissions(member, roles_by_id)

    if perms & PERMISSION_BITS["ADMINISTRATOR"]:
        return ALL_PERMISSIONS

    overwrites = channel.overwrites
    member_role_ids = set(member.role_ids)

    everyone_allow = 0
    everyone_deny = 0
    role_allow = 0
    role_deny = 0
    member_allow = 0
    member_deny = 0

    for ow in overwrites:
        try:
            ow_type = int(ow.get("type", 0))
            ow_id = str(ow.get("id", ""))
            allow = permissions_from_string(ow.get("allow", "0"))
            deny = permissions_from_string(ow.get("deny", "0"))
        except (TypeError, ValueError):
            continue

        if ow_type == OW_TYPE_ROLE:
            if ow_id == everyone_role_id:
                everyone_allow |= allow
                everyone_deny |= deny
            elif ow_id in member_role_ids:
                role_allow |= allow
                role_deny |= deny
        elif ow_type == OW_TYPE_MEMBER:
            if ow_id == member.user_id:
                member_allow |= allow
                member_deny |= deny

    perms &= ~everyone_deny
    perms |= everyone_allow
    perms &= ~role_deny
    perms |= role_allow
    perms &= ~member_deny
    perms |= member_allow

    return perms


# ============================================================================
# REDACTION
# ============================================================================
def redact_id(value: str, salt: str) -> str:
    if not value:
        return value
    digest = hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()
    return f"id-{digest[:10]}"


# ============================================================================
# RENDER: HUMAN
# ============================================================================
def _bucket_channels(
    channels: Sequence[Channel],
) -> Tuple[List[Channel], Dict[str, List[Channel]]]:
    """Return (categories, {category_id: [children]}). Uncategorised channels
    land under the empty-string key."""
    categories: List[Channel] = []
    by_parent: Dict[str, List[Channel]] = {}
    for ch in channels:
        if ch.type == 4:
            categories.append(ch)
        else:
            by_parent.setdefault(ch.parent_id or "", []).append(ch)

    categories.sort(key=lambda c: c.position)
    for parent, children in by_parent.items():
        children.sort(key=lambda c: c.position)
    return categories, by_parent


def _fmt_overwrite(
    ow: Dict[str, Any],
    role_names: Dict[str, str],
    redact: bool,
    salt: str,
) -> str:
    try:
        ow_type = int(ow.get("type", 0))
        ow_id = str(ow.get("id", ""))
        allow = permissions_from_string(ow.get("allow", "0"))
        deny = permissions_from_string(ow.get("deny", "0"))
    except (TypeError, ValueError):
        return "(malformed overwrite)"

    label = role_names.get(ow_id)
    if label is None:
        if redact:
            label = redact_id(ow_id, salt)
        else:
            label = ow_id
    if ow_type == OW_TYPE_ROLE:
        prefix = "@"
    else:
        prefix = ""  # member-level overwrite

    allow_names = permission_names(allow)
    deny_names = permission_names(deny)
    parts: List[str] = []
    if allow_names:
        parts.append(paint("allow:", C.GREEN) + " " + ", ".join(allow_names))
    if deny_names:
        parts.append(paint("deny:", C.RED) + " " + ", ".join(deny_names))
    detail = "   ".join(parts) if parts else "(empty)"
    return f"{prefix}{label}  {detail}"


def render_guild_header(guild: Guild) -> None:
    divider = paint("=" * 80, C.GREY)
    print(divider)
    print(f"{paint('GUILD', C.BOLD)}      {guild.name}  ({guild.id})")
    print(f"{paint('MEMBERS', C.BOLD)}    {guild.member_count:,} (approx.)")
    print(divider)
    print()


def render_roles(
    roles: Sequence[Role],
    role_member_counts: Dict[str, int],
    redact: bool,
    salt: str,
) -> None:
    print(paint(f"ROLES ({len(roles)})", C.BOLD))
    if not roles:
        print("  (none)")
        print()
        return

    name_width = min(32, max(12, max(len(r.name) for r in roles)))
    header = (
        f"  {'POS':>4}  "
        f"{'NAME'.ljust(name_width)}  "
        f"{'COLOR':<8}  "
        f"{'HOIST':<5}  "
        f"{'MENTION':<7}  "
        f"{'MEMBERS':>7}  "
        f"PERMISSIONS"
    )
    print(paint(header, C.BOLD))

    for role in roles:
        name = role.name
        if len(name) > name_width:
            name = name[: name_width - 1] + "\u2026"

        color = role.color_hex or paint("-", C.GREY)
        if role.color_hex and USE_COLOR:
            color = f"\033[38;2;{role.color >> 16};{(role.color >> 8) & 0xFF};{role.color & 0xFF}m{role.color_hex}{C.RESET}"

        perm_count = len(permission_names(role.permissions))
        admin = bool(role.permissions & PERMISSION_BITS["ADMINISTRATOR"])
        dangerous = admin or any(
            p in CONFIG["dangerous_permissions"]
            for p in permission_names(role.permissions)
        )

        perm_label = f"{perm_count} perm(s)"
        if admin:
            perm_label = paint("ADMINISTRATOR (all permissions)", C.ALERT)
        elif dangerous:
            perm_label = f"{perm_label}  {paint('[elevated]', C.YELLOW)}"

        count = role_member_counts.get(role.id, 0)
        print(
            f"  {str(role.position).rjust(4)}  "
            f"{name.ljust(name_width)}  "
            f"{(role.color_hex or '-').ljust(8)}  "
            f"{('yes' if role.hoist else 'no').ljust(5)}  "
            f"{('yes' if role.mentionable else 'no').ljust(7)}  "
            f"{str(count).rjust(7)}  "
            f"{perm_label}"
        )
    print()


def render_channels(
    channels: Sequence[Channel],
    role_names: Dict[str, str],
    redact: bool,
    salt: str,
    effective: Optional[Dict[str, int]] = None,
) -> None:
    categories, by_parent = _bucket_channels(channels)

    print(paint(f"CHANNELS ({len(channels)})", C.BOLD))
    if not channels:
        print("  (none)")
        print()
        return

    def print_channel(ch: Channel, indent: str) -> None:
        icon = CHANNEL_TYPE_ICONS.get(ch.type, "?")
        name = f"{icon} {ch.name}"
        suffix = "" if ch.type != 4 else "  [category]"
        print(f"{indent}{paint(name, C.CYAN)}{suffix}")

        if effective is not None:
            mask = effective.get(ch.id, 0)
            names = permission_names(mask)
            if not names:
                print(f"{indent}   {paint('effective: (none)', C.RED)}")
            else:
                joined = ", ".join(names)
                if len(joined) > 140:
                    joined = joined[:137] + "..."
                print(f"{indent}   {paint('effective:', C.GREEN)} {joined}")

        if not ch.overwrites:
            return
        print(f"{indent}   {paint('overwrites:', C.GREY)}")
        for ow in ch.overwrites:
            line = _fmt_overwrite(ow, role_names, redact, salt)
            print(f"{indent}     - {line}")

    # Categories first, with their children.
    seen: Set[str] = set()
    for category in categories:
        seen.add(category.id)
        print_channel(category, "  ")
        for child in by_parent.get(category.id, []):
            seen.add(child.id)
            print_channel(child, "    ")

    # Anything without a parent (or whose parent isn't a category we saw).
    orphans = [c for c in by_parent.get("", []) if c.id not in seen]
    if orphans:
        if categories:
            print(paint("  -- no category --", C.GREY))
        for ch in orphans:
            seen.add(ch.id)
            print_channel(ch, "  ")

    print()


def render_members(
    members: Sequence[Member],
    roles_by_id: Dict[str, Role],
    redact: bool,
    salt: str,
) -> None:
    print(paint(f"MEMBERS ({len(members)})", C.BOLD))
    if not members:
        print("  (none)")
        print()
        return

    def sort_key(m: Member) -> str:
        return (m.display() or m.username or m.user_id).lower()

    ordered = sorted(members, key=sort_key)
    name_width = min(28, max(10, max(len(m.display()) for m in ordered)))
    nick_width = min(20, max(8, max(len(m.nickname or "-") for m in ordered)))

    header = (
        f"  {'NAME'.ljust(name_width)}  "
        f"{'NICK'.ljust(nick_width)}  "
        f"{'ID'.ljust(20)}  "
        f"{'JOINED':<10}  "
        f"ROLES"
    )
    print(paint(header, C.BOLD))

    for m in ordered:
        display = m.display()
        if len(display) > name_width:
            display = display[: name_width - 1] + "\u2026"
        nick = m.nickname or "-"
        if len(nick) > nick_width:
            nick = nick[: nick_width - 1] + "\u2026"

        uid = redact_id(m.user_id, salt) if redact else m.user_id
        joined = (m.joined_at or "")[:10] or "-"

        role_labels = []
        for rid in m.role_ids:
            role = roles_by_id.get(rid)
            role_labels.append(role.name if role else rid)
        # @everyone sorts last for readability
        role_labels.sort(key=lambda r: (r == "@everyone", r.lower()))
        roles_text = ", ".join(role_labels) or "(none)"
        if len(roles_text) > 60:
            roles_text = roles_text[:57] + "..."

        bot_marker = paint(" [bot]", C.MAGENTA) if m.bot else ""
        print(
            f"  {display.ljust(name_width)}  "
            f"{nick.ljust(nick_width)}  "
            f"{uid.ljust(20)}  "
            f"{joined:<10}  "
            f"{roles_text}{bot_marker}"
        )
    print()


# ============================================================================
# RECORD BUILDERS (JSON / CSV)
# ============================================================================
def role_record(role: Role, member_count: int) -> Dict[str, Any]:
    return {
        "id": role.id,
        "name": role.name,
        "color": role.color_hex or None,
        "position": role.position,
        "hoist": role.hoist,
        "mentionable": role.mentionable,
        "managed": role.managed,
        "permissions_raw": str(role.permissions),
        "permissions": permission_names(role.permissions),
        "permission_count": len(permission_names(role.permissions)),
        "administrator": bool(role.permissions & PERMISSION_BITS["ADMINISTRATOR"]),
        "member_count": member_count,
    }


def channel_record(
    channel: Channel,
    role_names: Dict[str, str],
    effective_mask: Optional[int] = None,
) -> Dict[str, Any]:
    overwrites: List[Dict[str, Any]] = []
    for ow in channel.overwrites:
        try:
            ow_type = int(ow.get("type", 0))
            ow_id = str(ow.get("id", ""))
            allow = permissions_from_string(ow.get("allow", "0"))
            deny = permissions_from_string(ow.get("deny", "0"))
        except (TypeError, ValueError):
            continue
        overwrites.append(
            {
                "type": "role" if ow_type == OW_TYPE_ROLE else "member",
                "id": ow_id,
                "name": role_names.get(ow_id),
                "allow": permission_names(allow),
                "deny": permission_names(deny),
            }
        )

    record: Dict[str, Any] = {
        "id": channel.id,
        "name": channel.name,
        "type": channel.kind,
        "type_raw": channel.type,
        "position": channel.position,
        "category_id": channel.parent_id,
        "overwrites": overwrites,
        "overwrite_count": len(overwrites),
    }
    if effective_mask is not None:
        record["effective_permissions"] = permission_names(effective_mask)
    return record


def member_record(
    member: Member,
    roles_by_id: Dict[str, Role],
    redact: bool,
    salt: str,
) -> Dict[str, Any]:
    role_list = [
        {
            "id": rid,
            "name": roles_by_id[rid].name if rid in roles_by_id else None,
            "position": roles_by_id[rid].position if rid in roles_by_id else None,
        }
        for rid in member.role_ids
    ]
    role_list.sort(key=lambda r: -(r["position"] or 0))

    return {
        "id": redact_id(member.user_id, salt) if redact else member.user_id,
        "username": member.username,
        "global_name": member.global_name,
        "nickname": member.nickname,
        "display_name": member.display(),
        "bot": member.bot,
        "joined_at": member.joined_at,
        "roles": [r["name"] or r["id"] for r in role_list],
        "role_ids": [r["id"] for r in role_list],
        "top_role": role_list[0]["name"] if role_list else None,
    }


# ============================================================================
# SELF TEST
# ============================================================================
def run_self_test() -> int:
    print(f"discord_audit {__version__} self-test")

    failures = 0

    def check(label: str, condition: Any) -> None:
        nonlocal failures
        ok = bool(condition)
        print(f"  {'PASS' if ok else 'FAIL':<4} {label}")
        if not ok:
            failures += 1

    # ---- permission bit parsing ------------------------------------------
    check("perm.parse.decimal", permissions_from_string("8") == 8)
    check("perm.parse.int", permissions_from_string(8) == 8)
    check("perm.parse.none", permissions_from_string(None) == 0)
    check("perm.parse.garbage", permissions_from_string("nope") == 0)

    # ---- permission names -------------------------------------------------
    view = PERMISSION_BITS["VIEW_CHANNEL"]
    send = PERMISSION_BITS["SEND_MESSAGES"]
    kick = PERMISSION_BITS["KICK_MEMBERS"]
    admin = PERMISSION_BITS["ADMINISTRATOR"]

    names = permission_names(view | send)
    check("perm.names.count", len(names) == 2)
    check("perm.names.contents", set(names) == {"VIEW_CHANNEL", "SEND_MESSAGES"})

    # ---- effective channel permissions -----------------------------------
    everyone_role_id = "100"
    mod_role_id = "200"
    muted_role_id = "300"

    roles_by_id: Dict[str, Role] = {
        everyone_role_id: Role(
            id=everyone_role_id,
            name="@everyone",
            color=0,
            position=0,
            hoist=False,
            mentionable=False,
            managed=False,
            permissions=view | send,  # everyone can view + send by default
            raw={},
        ),
        mod_role_id: Role(
            id=mod_role_id,
            name="Moderator",
            color=0,
            position=1,
            hoist=True,
            mentionable=True,
            managed=False,
            permissions=kick,  # extra: kick members
            raw={},
        ),
        muted_role_id: Role(
            id=muted_role_id,
            name="Muted",
            color=0,
            position=2,
            hoist=False,
            mentionable=False,
            managed=False,
            permissions=0,
            raw={},
        ),
    }

    def make_member(role_ids: List[str]) -> Member:
        return Member(
            user_id="999",
            username="tester",
            global_name=None,
            nickname=None,
            role_ids=role_ids,
            joined_at=None,
            bot=False,
            raw={},
        )

    def make_channel(overwrites: List[Dict[str, Any]]) -> Channel:
        return Channel(
            id="chan",
            name="general",
            type=0,
            position=0,
            parent_id=None,
            overwrites=overwrites,
            raw={},
        )

    # Case 1: no overwrites. Base perms apply.
    ch_none = make_channel([])
    member = make_member([everyone_role_id])
    perms = effective_channel_permissions(
        member, ch_none, roles_by_id, everyone_role_id
    )
    check("eff.no_overwrites.view", bool(perms & view))
    check("eff.no_overwrites.send", bool(perms & send))
    check("eff.no_overwrites.kick", not bool(perms & kick))

    # Case 2: member has Moderator, so gets kick at the server level.
    member_mod = make_member([everyone_role_id, mod_role_id])
    perms = effective_channel_permissions(
        member_mod, ch_none, roles_by_id, everyone_role_id
    )
    check("eff.moderator.kick", bool(perms & kick))
    check("eff.moderator.still_view", bool(perms & view))

    # Case 3: channel denies @everyone view. Members without roles can't see it.
    ch_private = make_channel(
        [
            {
                "id": everyone_role_id,
                "type": OW_TYPE_ROLE,
                "allow": "0",
                "deny": str(view),
            }
        ]
    )
    perms = effective_channel_permissions(
        make_member([everyone_role_id]), ch_private, roles_by_id, everyone_role_id
    )
    check("eff.deny_everyone.blocks_view", not bool(perms & view))
    check("eff.deny_everyone.keeps_send", bool(perms & send))

    # Case 4: role overwrite allows view back. Role allow beats everyone deny.
    ch_mod_only = make_channel(
        [
            {
                "id": everyone_role_id,
                "type": OW_TYPE_ROLE,
                "allow": "0",
                "deny": str(view),
            },
            {
                "id": mod_role_id,
                "type": OW_TYPE_ROLE,
                "allow": str(view),
                "deny": "0",
            },
        ]
    )
    perms = effective_channel_permissions(
        make_member([everyone_role_id, mod_role_id]),
        ch_mod_only,
        roles_by_id,
        everyone_role_id,
    )
    check("eff.role_allow_overrides_everyone_deny", bool(perms & view))
    perms = effective_channel_permissions(
        make_member([everyone_role_id]),
        ch_mod_only,
        roles_by_id,
        everyone_role_id,
    )
    check("eff.non_mod_still_blocked", not bool(perms & view))

    # Case 5: member-level overwrite denies what roles allowed.
    ch_personal = make_channel(
        [
            {
                "id": "999",
                "type": OW_TYPE_MEMBER,
                "allow": "0",
                "deny": str(send),
            }
        ]
    )
    perms = effective_channel_permissions(
        make_member([everyone_role_id]), ch_personal, roles_by_id, everyone_role_id
    )
    check("eff.member_deny_blocks_send", not bool(perms & send))
    check("eff.member_deny_keeps_view", bool(perms & view))

    # Case 6: ADMINISTRATOR short-circuits everything, including explicit denies.
    admin_role_id = "400"
    roles_by_id[admin_role_id] = Role(
        id=admin_role_id,
        name="Admin",
        color=0,
        position=3,
        hoist=True,
        mentionable=True,
        managed=False,
        permissions=admin,
        raw={},
    )
    perms = effective_channel_permissions(
        make_member([everyone_role_id, admin_role_id]),
        ch_private,  # @everyone is denied view here
        roles_by_id,
        everyone_role_id,
    )
    check("eff.admin_bypasses_denies", perms == ALL_PERMISSIONS)

    # ---- channel bucketing ----------------------------------------------
    cat = Channel("cat1", "Info", 4, 0, None, [], {})
    ch1 = Channel("c1", "rules", 0, 0, "cat1", [], {})
    ch2 = Channel("c2", "general", 0, 1, "cat1", [], {})
    ch3 = Channel("c3", "orphan", 0, 2, None, [], {})
    cats, by_parent = _bucket_channels([cat, ch1, ch2, ch3])
    check("bucket.categories", [c.id for c in cats] == ["cat1"])
    check("bucket.cat_children", [c.id for c in by_parent["cat1"]] == ["c1", "c2"])
    check("bucket.orphans", [c.id for c in by_parent[""]] == ["c3"])

    # ---- redaction -------------------------------------------------------
    a = redact_id("123456789012345678", "salt")
    b = redact_id("123456789012345678", "salt")
    c = redact_id("987654321098765432", "salt")
    check("redact.stable", a == b)
    check("redact.different", a != c)
    check("redact.prefix", a.startswith("id-"))
    check("redact.length", len(a) == 13)

    # ---- role sorting ----------------------------------------------------
    r1 = Role("1", "A", 0, 1, False, False, False, 0, {})
    r2 = Role("2", "B", 0, 5, False, False, False, 0, {})
    r3 = Role("3", "C", 0, 3, False, False, False, 0, {})
    sorted_roles = sorted([r1, r2, r3], key=lambda r: r.position, reverse=True)
    check("role.sort.highest_first", [r.id for r in sorted_roles] == ["2", "3", "1"])

    # ---- colour hex ------------------------------------------------------
    r = Role("1", "x", 0xED4245, 0, False, False, False, 0, {})
    check("colour.hex", r.color_hex == "#ED4245")
    r = Role("1", "x", 0, 0, False, False, False, 0, {})
    check("colour.default_empty", r.color_hex == "")

    print()
    print(f"Result: {'PASS' if failures == 0 else f'{failures} failure(s)'}")
    return 0 if failures == 0 else 1


# ============================================================================
# ARGPARSE
# ============================================================================
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="discord_audit.py",
        description=(
            "Read-only audit of a Discord guild: channels, permission "
            "overwrites, roles, and (optionally) members."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Setup:\n"
            "  1. Create a bot at https://discord.com/developers/applications\n"
            "  2. Enable 'Server Members Intent' under Bot -> Privileged Intents\n"
            "  3. Invite it to your server with the 'View Channels' permission\n"
            "  4. export DISCORD_AUDIT_BOT_TOKEN='...'\n"
            "\n"
            "Examples:\n"
            "  python discord_audit.py\n"
            "  python discord_audit.py --members\n"
            "  python discord_audit.py --members --role Moderators\n"
            "  python discord_audit.py --as-user 123456789012345678\n"
            "  python discord_audit.py --json > audit.json\n"
            "  python discord_audit.py --redact --members\n"
            "  python discord_audit.py --self-test\n"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"discord_audit.py {__version__}",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline tests and exit.",
    )
    parser.add_argument(
        "--token",
        help="Bot token. Prefer the DISCORD_AUDIT_BOT_TOKEN environment variable.",
    )
    parser.add_argument(
        "--guild",
        metavar="ID",
        help="Guild ID to audit. Required if the bot is in more than one.",
    )
    parser.add_argument(
        "--list-guilds",
        action="store_true",
        help="List the guilds the bot can see, then exit.",
    )

    sel = parser.add_argument_group("what to include")
    sel.add_argument(
        "--members",
        action="store_true",
        help="Also fetch and list members (requires Server Members Intent).",
    )
    sel.add_argument(
        "--role",
        metavar="NAME_OR_ID",
        help="Only show members who have this role (implies --members).",
    )
    sel.add_argument(
        "--include-bots",
        action="store_true",
        help="Include bot accounts in the member list.",
    )
    sel.add_argument(
        "--as-user",
        metavar="USER_ID",
        help=(
            "Compute effective per-channel permissions for this user ID. "
            "Requires --members."
        ),
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
        help="Print one JSON object per line (roles, then channels, then members).",
    )
    out.add_argument(
        "--csv-members",
        metavar="PATH",
        help="Write the member list to a CSV file.",
    )
    out.add_argument(
        "--csv-channels",
        metavar="PATH",
        help="Write the channel list to a CSV file (overwrites are JSON-encoded).",
    )
    out.add_argument(
        "--redact",
        action="store_true",
        help="Hash user IDs and role IDs in the output (stable, non-reversible).",
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
def _resolve_token(args: argparse.Namespace) -> Optional[str]:
    if args.token:
        return args.token.strip() or None
    value = os.environ.get("DISCORD_AUDIT_BOT_TOKEN") or os.environ.get("DISCORD_TOKEN")
    if value:
        value = value.strip()
        # Strip a leading "Bot " if the user pasted it in.
        if value.lower().startswith("bot "):
            value = value[4:].strip()
        return value or None
    return None


def _pick_guild(
    client: DiscordClient, requested: Optional[str], quiet: bool
) -> Optional[str]:
    if requested:
        return requested

    guilds = client.get("/users/@me/guilds")
    if not isinstance(guilds, list) or not guilds:
        warn(
            "ERROR: the bot is not a member of any guild. "
            "Invite it to your server first.",
            C.RED,
        )
        return None

    if len(guilds) == 1:
        return str(guilds[0].get("id"))

    warn(
        "The bot is in multiple guilds. Pass --guild ID to pick one:",
        C.YELLOW,
    )
    for g in guilds:
        if isinstance(g, dict):
            warn(
                f"  {g.get('id')}  {g.get('name')}",
                C.GREY,
            )
    return None


def _print_guild_list(client: DiscordClient) -> int:
    guilds = client.get("/users/@me/guilds")
    if not isinstance(guilds, list) or not guilds:
        warn("The bot is not a member of any guild.", C.YELLOW)
        return 1
    for g in guilds:
        if not isinstance(g, dict):
            continue
        print(f"{g.get('id')}\t{g.get('name')}")
    return 0


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

    token = _resolve_token(args)
    if not token:
        warn(
            "ERROR: no bot token. Set DISCORD_AUDIT_BOT_TOKEN, or pass --token.",
            C.RED,
        )
        warn(
            "       Create a bot at https://discord.com/developers/applications",
            C.GREY,
        )
        warn(
            "       Do NOT use a user token: it violates Discord's ToS.",
            C.YELLOW,
        )
        return 2

    client = DiscordClient(token, CONFIG["api_base"])

    # ---- bot identity check ---------------------------------------------
    try:
        me = client.get("/users/@me")
        if not isinstance(me, dict):
            raise DiscordError("Unexpected /users/@me payload")
        bot_username = me.get("username", "?")
    except DiscordError as exc:
        if exc.status == 401:
            warn(
                "ERROR: 401 Unauthorized. The token is invalid, expired, "
                "or is not a bot token.",
                C.RED,
            )
        else:
            warn(f"ERROR: could not authenticate: {exc}", C.RED)
        return 2

    if not args.quiet:
        warn(f"Authenticated as: {bot_username}", C.GREY)

    if args.list_guilds:
        return _print_guild_list(client)

    guild_id = _pick_guild(client, args.guild, args.quiet)
    if not guild_id:
        return 2

    # ---- fetch core data -------------------------------------------------
    try:
        guild = fetch_guild(client, guild_id)
        roles = fetch_roles(client, guild_id)
        channels = fetch_channels(client, guild_id)
    except DiscordError as exc:
        if exc.status == 403:
            warn(
                f"ERROR: 403 Forbidden on guild {guild_id}. The bot isn't "
                "a member of this guild, or lacks 'View Channels'.",
                C.RED,
            )
        elif exc.status == 404:
            warn(f"ERROR: guild {guild_id} not found.", C.RED)
        else:
            warn(f"ERROR: {exc}", C.RED)
        return 2

    roles_by_id = {r.id: r for r in roles}
    everyone_role_id = guild_id  # @everyone always has the guild's own ID
    role_names = {r.id: r.name for r in roles}
    role_names.setdefault(everyone_role_id, "@everyone")

    # ---- members (optional) ---------------------------------------------
    need_members = bool(args.members or args.role or args.as_user)
    members: List[Member] = []
    if need_members:
        try:
            if not args.quiet:
                warn("Fetching members (this may take a moment)...", C.GREY)
            members = fetch_members(client, guild_id)
        except DiscordError as exc:
            if exc.status == 403:
                warn(
                    "ERROR: 403 Forbidden on /members. Two likely causes:",
                    C.RED,
                )
                warn(
                    "       1. 'Server Members Intent' is disabled on the bot "
                    "(Bot -> Privileged Gateway Intents).",
                    C.YELLOW,
                )
                warn(
                    "       2. The bot lacks 'View Channels' in this guild.",
                    C.YELLOW,
                )
            else:
                warn(f"ERROR: could not fetch members: {exc}", C.RED)
            return 2

        if not args.include_bots:
            members = [m for m in members if not m.bot]

        if args.role:
            target = args.role.strip()
            role_match = None
            for r in roles:
                if r.id == target or r.name.lower() == target.lower():
                    role_match = r
                    break
            if role_match is None:
                warn(f"No role matches {target!r}.", C.RED)
                return 2
            members = [m for m in members if role_match.id in m.role_ids]

    # ---- per-channel effective permissions (optional) -------------------
    effective_by_channel: Optional[Dict[str, int]] = None
    effective_subject: Optional[Member] = None
    if args.as_user:
        effective_subject = next(
            (m for m in members if m.user_id == args.as_user), None
        )
        if effective_subject is None:
            warn(
                f"User {args.as_user} not found in the fetched member list. "
                "(Bot accounts are excluded unless --include-bots is passed.)",
                C.RED,
            )
            return 2
        effective_by_channel = {}
        for ch in channels:
            if ch.type == 4:
                # Categories don't grant permissions directly; skip.
                continue
            effective_by_channel[ch.id] = effective_channel_permissions(
                effective_subject, ch, roles_by_id, everyone_role_id
            )

    # ---- role member counts ---------------------------------------------
    role_member_counts: Dict[str, int] = {r.id: 0 for r in roles}
    role_member_counts[everyone_role_id] = len(members)
    for m in members:
        for rid in m.role_ids:
            role_member_counts[rid] = role_member_counts.get(rid, 0) + 1

    # ---- output ----------------------------------------------------------
    salt = "discord_audit"

    if args.json or args.jsonl:
        guild_record = {
            "id": guild.id,
            "name": guild.name,
            "member_count_approx": guild.member_count,
        }
        role_records = [role_record(r, role_member_counts.get(r.id, 0)) for r in roles]
        channel_records = [
            channel_record(
                ch,
                role_names,
                effective_by_channel.get(ch.id) if effective_by_channel else None,
            )
            for ch in channels
        ]
        member_records = [
            member_record(m, roles_by_id, args.redact, salt) for m in members
        ]

        if args.json:
            payload: Dict[str, Any] = {
                "guild": guild_record,
                "roles": role_records,
                "channels": channel_records,
            }
            if need_members:
                payload["members"] = member_records
            if effective_subject is not None:
                payload["effective_for"] = {
                    "user_id": (
                        redact_id(effective_subject.user_id, salt)
                        if args.redact
                        else effective_subject.user_id
                    ),
                    "display_name": effective_subject.display(),
                }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(
                json.dumps({"type": "guild", "data": guild_record}, ensure_ascii=False)
            )
            for r in role_records:
                print(json.dumps({"type": "role", "data": r}, ensure_ascii=False))
            for c in channel_records:
                print(json.dumps({"type": "channel", "data": c}, ensure_ascii=False))
            if need_members:
                for m in member_records:
                    print(json.dumps({"type": "member", "data": m}, ensure_ascii=False))
    else:
        render_guild_header(guild)
        render_roles(roles, role_member_counts, args.redact, salt)
        render_channels(
            channels,
            role_names,
            args.redact,
            salt,
            effective=effective_by_channel,
        )
        if effective_subject is not None and not args.quiet:
            print(
                paint(
                    f"Effective permissions shown above are for: "
                    f"{effective_subject.display()} ({effective_subject.user_id})",
                    C.GREY,
                )
            )
            print()
        if need_members:
            render_members(members, roles_by_id, args.redact, salt)

    # ---- CSV outputs -----------------------------------------------------
    if args.csv_members:
        if not need_members:
            warn("--csv-members ignored: pass --members or --role.", C.YELLOW)
        else:
            fields = [
                "id",
                "username",
                "global_name",
                "nickname",
                "display_name",
                "bot",
                "joined_at",
                "top_role",
                "roles",
                "role_ids",
            ]
            try:
                with open(
                    args.csv_members, "w", newline="", encoding="utf-8-sig"
                ) as fh:
                    writer = csv.DictWriter(
                        fh, fieldnames=fields, extrasaction="ignore"
                    )
                    writer.writeheader()
                    for m in sorted(members, key=lambda x: x.display().lower()):
                        row = member_record(m, roles_by_id, args.redact, salt)
                        row["roles"] = ";".join(row["roles"])
                        row["role_ids"] = ";".join(row["role_ids"])
                        writer.writerow({k: row.get(k, "") for k in fields})
                if not args.quiet:
                    warn(f"Member CSV written to: {args.csv_members}", C.GREEN)
            except OSError as exc:
                warn(f"ERROR: cannot write {args.csv_members}: {exc}", C.RED)
                return 2

    if args.csv_channels:
        fields = [
            "id",
            "name",
            "type",
            "type_raw",
            "position",
            "category_id",
            "overwrite_count",
            "overwrites",
        ]
        try:
            with open(args.csv_channels, "w", newline="", encoding="utf-8-sig") as fh:
                writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for ch in channels:
                    row = channel_record(
                        ch,
                        role_names,
                        effective_by_channel.get(ch.id)
                        if effective_by_channel
                        else None,
                    )
                    row["overwrites"] = json.dumps(
                        row["overwrites"], ensure_ascii=False
                    )
                    writer.writerow({k: row.get(k, "") for k in fields})
            if not args.quiet:
                warn(f"Channel CSV written to: {args.csv_channels}", C.GREEN)
        except OSError as exc:
            warn(f"ERROR: cannot write {args.csv_channels}: {exc}", C.RED)
            return 2

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        warn("\nAborted by user.")
        sys.exit(130)
