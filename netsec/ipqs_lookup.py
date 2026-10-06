#!/usr/bin/env python3
"""
=====================================================================================
SCRIPT NAME:      ipqs_lookup.py
VERSION:          4.0

DESCRIPTION:
    IPQualityScore (IPQS) Proxy / VPN / IP reputation lookup tool.

    Pulls every field the API returns (VPN / proxy / Tor / bot / crawler /
    abuse history / connection type / geo / device / transaction) and produces
    a transparent, two-layer verdict:

      1) IPQS Fraud Score classification (official, from the API)
      2) Local evidence score (transparent, weighted, from the tool)

    The custom score is never presented as IPQS's own score.

USAGE
-----
    python ipqs_lookup.py                              # uses CONFIG["target_ips"]
    python ipqs_lookup.py 8.8.8.8
    python ipqs_lookup.py 8.8.8.8 1.1.1.1 2606:4700:4700::1111
    python ipqs_lookup.py --file ips.txt
    type ips.txt | python ipqs_lookup.py -
    python ipqs_lookup.py 8.8.8.8 --json
    python ipqs_lookup.py 8.8.8.8 --jsonl --redact
    python ipqs_lookup.py --file ips.txt --csv results.csv --only-flagged
    python ipqs_lookup.py --file ips.txt --report --fields fraud_score,proxy,vpn,reasons
    python ipqs_lookup.py 8.8.8.8 --user-agent "Mozilla/5.0 ..." --user-language en-NZ
    python ipqs_lookup.py 8.8.8.8 --strictness 1 --transaction-strictness 1
    python ipqs_lookup.py 8.8.8.8 --field billing_phone=64211234567 --field billing_country=NZ
    python ipqs_lookup.py --config ipqs.json --refresh
    python ipqs_lookup.py --postback 1a2b3c4d
    python ipqs_lookup.py --self-test

API KEY
-------
    Preferred: set the IPQS_API_KEY environment variable.
    Fallback:  CONFIG["api_key"] below.
    Or:        --api-key on the command line.
    Or:        "api_key" inside a --config JSON file.
    The key is sent in the IPQS-KEY header by default, so it never appears
    in a URL.

DEFAULT REQUEST SETTINGS (and why)
----------------------------------
    strictness=0                    IPQS: start at 0 and increase to 1 only if
                                    you need it. Levels 2+ are VERY strict and
                                    produce false positives.
    allow_public_access_points=true Recommended by IPQS to avoid false positives
                                    on universities, hotels, corporate ranges.
    lighter_penalties=false         true would LOWER detection rates.
    fast=false                      true skips slower forensic checks.
    mobile / user_agent / language  Only sent if you supply them (a made-up user
                                    agent would skew the score).

REQUIREMENTS
------------
    - Python 3.8+
    - IPQualityScore API key: https://www.ipqualityscore.com/

Copyright (c) 2026 Jericho Crosby (Chalwk)
LICENSE: MIT
=====================================================================================
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import ipaddress
import json
import os
import random
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


__version__ = "4.0"


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
# TYPE ALIASES
# ============================================================================
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


# ============================================================================
# CONFIG
# ============================================================================
CONFIG: Dict[str, Any] = {
    # IPQS API key. Prefer the IPQS_API_KEY environment variable.
    "api_key": "",
    # Endpoint (override with IPQS_API_URL env var, handy for proxies/testing).
    "api_url": "https://ipqualityscore.com/api/json/ip",
    # True  = send key in the IPQS-KEY header (keeps it out of URLs and logs).
    # False = classic /api/json/ip/KEY/IP path style.
    "key_in_header": True,
    # POST (default) or GET. POST is safer with PII-bearing parameters.
    "method": "POST",
    # ------------------------------------------------------------------
    # MANUAL LOOKUP LIST (used when no IPs are passed on the command line)
    # ------------------------------------------------------------------
    "target_ips": [
        "xxx.xxx.xxx.xxx",
    ],
    # Full report per IP (True) or one compact line per IP (False).
    "log_verbose": True,
    # IPs / CIDR ranges that are never looked up (saves credits).
    "exclusion_list": [
        "127.0.0.1",
        "::1",
        # "10.0.0.0/8",
    ],
    # Skip private / loopback / reserved / otherwise non-public addresses.
    "skip_non_public": True,
    # ------------------------------------------------------------------
    # REQUEST PARAMETERS  (see the "Advanced Options" docs page)
    # ------------------------------------------------------------------
    "parameters": {
        "strictness": 0,                        # 0-3. 0 recommended.
        "allow_public_access_points": True,     # recommended by IPQS
        "lighter_penalties": False,             # True lowers detection rates
        "fast": False,                          # False = slower forensic checks
        "mobile": None,                         # Only sent if you set it
        "user_agent": None,                     # Real visitor UA
        "user_language": None,                  # e.g. "en-US"
        "transaction_strictness": None,         # 0-2. Only useful with tx data.
    },
    # Arbitrary extra API variables. Key expansion point for billing_phone,
    # billing_address_1, transaction fields, device_id, etc.
    "request_fields": {},
    # Custom tracking variables defined in your IPQS account settings.
    # e.g. {"userID": "555", "transactionID": "234499"}
    "custom_variables": {},
    # ------------------------------------------------------------------
    # NETWORK BEHAVIOUR
    # ------------------------------------------------------------------
    "network": {
        "timeout": 20.0,        # seconds per request
        "retries": 4,           # extra attempts on timeouts / 429 / 5xx
        "backoff": 1.0,         # base seconds; doubles each retry (+ jitter)
        "max_backoff": 30.0,    # hard cap on any single sleep
        "workers": 6,           # parallel lookups
        "max_rps": 5.0,         # max requests started per second (0 = unlimited)
    },
    # ------------------------------------------------------------------
    # CACHE  (each uncached lookup costs an IPQS credit)
    # ------------------------------------------------------------------
    "cache": {
        "enabled": True,
        "ttl_hours": 6,
        "path": None,   # None = per-user cache dir
        "schema": 4,    # bump when the on-disk shape changes
        # Never persist responses for requests containing obvious PII.
        "disable_for_sensitive_requests": True,
    },
    # ------------------------------------------------------------------
    # LOCAL VERDICT SCORING
    #
    # This is the tool's own evidence-based verdict, deliberately separate
    # from IPQS's fraud_score classification. Thresholds align with IPQS's
    # published bands (75 = suspicious, 90 = high risk / block).
    #
    # IPQS: >=75 suspicious, >=85 high risk, >=90 recommended block.
    # ------------------------------------------------------------------
    "local_verdicts": {
        "caution": 40,      # >= this -> CAUTION
        "suspicious": 75,   # >= this -> SUSPICIOUS
        "high_risk": 90,    # >= this -> HIGH RISK
    },
    "local_weights": {
        "active_tor": 45,
        "high_risk_attacks": 40,
        "frequent_abuser": 30,
        "active_vpn": 25,
        "recent_abuse": 25,
        "bot_status": 25,
        "proxy": 20,
        "tor": 20,
        "vpn": 15,
        "abuse_velocity": {"high": 25, "medium": 12, "low": 4},
        "data_center": 10,
        "security_scanner": 0,
        "is_crawler": 0,
        "trusted_network": -20,
        "abuse_event": 6,       # per distinct abuse event type...
        "abuse_event_cap": 24,  # ...up to this total
        "transaction_risk_multiplier": 1.0,
    },
}


API_URL_DEFAULT = CONFIG["api_url"]
PLACEHOLDER_KEYS = {"", "PASTE_API_KEY_HERE", "YOUR_API_KEY_HERE", "REDACTED"}

# Enterprise data points: absent on some plans.
ENTERPRISE_FLAGS: Tuple[str, ...] = (
    "frequent_abuser",
    "high_risk_attacks",
    "shared_connection",
    "dynamic_connection",
    "security_scanner",
    "trusted_network",
)

# Response fields that come from adjacent IPQS APIs (e.g., Device
# Fingerprinting) and may appear in enriched responses.
DEVICE_FIELDS: Tuple[str, ...] = (
    "device_id",
    "guid",
    "guid_confidence",
    "fraud_chance",
    "ssl_fingerprint",
    "device_timezone",
    "high_risk_device",
)

KNOWN_FIELDS = {
    "success",
    "message",
    "errors",
    "request_id",
    "IP",
    "fraud_score",
    "proxy",
    "vpn",
    "tor",
    "active_vpn",
    "active_tor",
    "bot_status",
    "is_crawler",
    "recent_abuse",
    "abuse_velocity",
    "frequent_abuser",
    "high_risk_attacks",
    "shared_connection",
    "dynamic_connection",
    "security_scanner",
    "trusted_network",
    "connection_type",
    "mobile",
    "public_access_point",
    "country_code",
    "region",
    "city",
    "zip_code",
    "latitude",
    "longitude",
    "timezone",
    "ISP",
    "organization",
    "Organization",
    "ASN",
    "host",
    "operating_system",
    "browser",
    "device_brand",
    "device_model",
    "abuse_events",
    "transaction_details",
    "recent_data_matches",
    "recent_unique_user_values",
    "reasons",  # Premium: fraud score insights
} | set(DEVICE_FIELDS)

VERDICT_ORDER = ["CLEAN", "CAUTION", "SUSPICIOUS", "HIGH RISK"]
VERDICT_RANK = {"HIGH RISK": 3, "SUSPICIOUS": 2, "CAUTION": 1, "CLEAN": 0}

SENSITIVE_FIELD_RE = re.compile(
    r"(?:^|_)(?:phone|email|address|postcode|postal|name|device_id|ip_address|"
    r"credit|card|payment|username|billing|shipping)(?:$|_)",
    re.I,
)

# ------------------------------------------------------------------
# Field selection (--fields)
#
# The union of both tools' export fields. Users may request a subset with
# --fields for CSV / JSON / JSONL.
# ------------------------------------------------------------------
ALL_EXPORT_FIELDS: List[str] = [
    "ip",
    "verdict",
    "ipqs_verdict",
    "risk_points",
    "fraud_score",
    "evidence_score",
    "transaction_risk_score",
    "tags",
    "signals",
    "reasons",
    "proxy",
    "vpn",
    "active_vpn",
    "tor",
    "active_tor",
    "bot_status",
    "is_crawler",
    "recent_abuse",
    "abuse_velocity",
    "frequent_abuser",
    "high_risk_attacks",
    "shared_connection",
    "dynamic_connection",
    "security_scanner",
    "trusted_network",
    "connection_type",
    "mobile",
    "public_access_point",
    "country_code",
    "region",
    "city",
    "zip_code",
    "latitude",
    "longitude",
    "timezone",
    "ISP",
    "organization",
    "ASN",
    "host",
    "abuse_events",
    "operating_system",
    "browser",
    "device_brand",
    "device_model",
    "request_id",
    "method",
    "http_status",
    "elapsed_ms",
    "cached",
    "error",
]

CSV_FIELDS = ALL_EXPORT_FIELDS


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

VERDICT_COLORS: Dict[str, str] = {
    "CLEAN": C.GREEN,
    "CAUTION": C.YELLOW,
    "SUSPICIOUS": C.RED,
    "HIGH RISK": C.ALERT,
    "ERROR": C.RED,
    "UNKNOWN": C.GREY,
}

BAD_TAGS = {
    "PROXY",
    "VPN",
    "ACTIVE-VPN",
    "TOR",
    "ACTIVE-TOR",
    "BOT",
    "RECENT-ABUSE",
    "FREQUENT-ABUSER",
    "HIGH-RISK-ATTACKS",
    "DATACENTER",
}
INFO_TAGS = {"CRAWLER", "SCANNER", "SHARED", "DYNAMIC"}


def paint(text: Any, code: str) -> str:
    text = str(text)
    return f"{code}{text}{C.RESET}" if USE_COLOR and code else text


def pad(text: Any, width: int, code: str = "") -> str:
    """Pad BEFORE colouring so ANSI codes don't wreck column alignment."""
    return paint(str(text).ljust(width), code)


def warn(msg: str, code: str = C.YELLOW) -> None:
    print(paint(msg, code), file=sys.stderr)


def tag_color(tag: str) -> str:
    if tag in BAD_TAGS:
        return C.RED
    if tag in INFO_TAGS:
        return C.MAGENTA
    if tag == "TRUSTED":
        return C.GREEN
    return C.CYAN


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


# ============================================================================
# CONFIGURATION
# ============================================================================
def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config_file(path: str) -> None:
    global CONFIG
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"ERROR: cannot load config {path}: {exc}")
    if not isinstance(data, dict):
        raise SystemExit(f"ERROR: config {path} must contain a JSON object")
    CONFIG = deep_merge(CONFIG, data)


def parse_key_value(items: Sequence[str], option_name: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"{option_name} expects KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise SystemExit(f"{option_name} received an empty key: {item!r}")
        result[key] = value.strip()
    return result


def normalize_request_value(value: str) -> Any:
    low = value.strip().lower()
    if low in {"true", "false"}:
        return low == "true"
    if low == "null":
        return None
    # JSON arrays/objects are useful for some advanced IPQS fields.
    if value.strip().startswith(("{", "[")):
        try:
            return json.loads(value)
        except ValueError:
            pass
    return value


def resolve_fields(
    requested: Optional[Sequence[str]],
    default: Sequence[str],
) -> List[str]:
    """
    Return the effective export field list.

    - No --fields: use the default ordering.
    - --fields given: preserve user ordering, allow arbitrary data keys.
    """
    if not requested:
        return list(default)

    result: List[str] = []
    for item in requested:
        for name in str(item).split(","):
            name = name.strip()
            if name and name not in result:
                result.append(name)
    return result


# ============================================================================
# HELPERS: IPs / API KEY / SENSITIVE DETECTION
# ============================================================================
def parse_ip(text: str) -> Optional[IPAddress]:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def build_exclusions() -> List[IPNetwork]:
    nets: List[IPNetwork] = []
    for item in CONFIG.get("exclusion_list", []):
        try:
            nets.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            warn(f"Ignoring bad exclusion_list entry: {item!r}")
    return nets


def is_excluded(ip: IPAddress, nets: Sequence[IPNetwork]) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def get_api_key() -> Optional[str]:
    key = (os.environ.get("IPQS_API_KEY") or CONFIG.get("api_key") or "").strip()
    return None if key.upper() in PLACEHOLDER_KEYS else key


def default_cache_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "ipqs_lookup" / "cache.json"


def request_contains_sensitive_fields(params: Dict[str, Any]) -> bool:
    for key in params:
        if SENSITIVE_FIELD_RE.search(str(key)):
            return True
    return False


# ============================================================================
# CACHE
# ============================================================================
class Cache:
    """Small JSON cache with atomic writes and schema-aware entries."""

    def __init__(
        self,
        enabled: bool,
        ttl_hours: float,
        path: Optional[Union[str, Path]] = None,
        refresh: bool = False,
        allow_sensitive: bool = False,
        schema: int = 4,
    ) -> None:
        self.enabled = bool(enabled)
        self.ttl = max(0.0, float(ttl_hours)) * 3600
        self.path = Path(path) if path else default_cache_path()
        self.refresh = refresh
        self.allow_sensitive = allow_sensitive
        self.schema = int(schema)
        self.lock = threading.Lock()
        self.entries: Dict[str, Dict[str, Any]] = {}
        self.dirty = False

        if self.enabled:
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    if raw.get("schema") == self.schema and isinstance(
                        raw.get("entries"), dict
                    ):
                        self.entries = raw["entries"]
                    elif all(isinstance(v, dict) for v in raw.values()):
                        # Accept legacy v2.x/v3.x flat caches as migration path.
                        self.entries = raw
            except (OSError, ValueError):
                self.entries = {}

    @staticmethod
    def key(ip: str, params: Dict[str, Any]) -> str:
        blob = json.dumps(
            {"ip": ip, "p": params}, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def get(self, key: str, sensitive: bool = False) -> Optional[Dict[str, Any]]:
        if not self.enabled or self.refresh:
            return None
        if sensitive and not self.allow_sensitive:
            return None
        with self.lock:
            entry = self.entries.get(key)
        if not isinstance(entry, dict):
            return None
        ts = float(entry.get("ts", 0))
        if time.time() - ts > self.ttl:
            return None
        data = entry.get("data")
        return data if isinstance(data, dict) else None

    def put(self, key: str, data: Dict[str, Any], sensitive: bool = False) -> None:
        if not self.enabled or (sensitive and not self.allow_sensitive):
            return
        with self.lock:
            self.entries[key] = {"ts": time.time(), "data": data}
            self.dirty = True

    def save(self) -> None:
        if not (self.enabled and self.dirty):
            return

        now = time.time()
        with self.lock:
            self.entries = {
                key: value
                for key, value in self.entries.items()
                if isinstance(value, dict)
                and now - float(value.get("ts", 0)) <= self.ttl
            }
            payload = {"schema": self.schema, "entries": self.entries}

        tmp_path: Optional[str] = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self.path.parent),
                prefix=".ipqs-cache-",
                suffix=".tmp",
                text=True,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            os.replace(tmp_path, self.path)
        except OSError as exc:
            warn(f"Could not write cache: {exc}", C.YELLOW)
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass


# ============================================================================
# RATE LIMITER
# ============================================================================
class RateLimiter:
    """Spaces out request start times across all worker threads."""

    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / rps if rps and rps > 0 else 0.0
        self.lock = threading.Lock()
        self.next_slot = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_slot - now)
            self.next_slot = max(now, self.next_slot) + self.interval
        if delay:
            time.sleep(delay)


# ============================================================================
# API CLIENT
# ============================================================================
class IPQSError(RuntimeError):
    def __init__(
        self,
        message: str,
        retryable: bool = False,
        fatal: bool = False,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.fatal = fatal
        self.retry_after = retry_after


def _bool_str(value: Any) -> str:
    return "true" if bool(value) else "false"


def build_params() -> Dict[str, Any]:
    """Request parameters (excluding ip / key). Only sends what's set."""
    p = CONFIG["parameters"]
    params: Dict[str, Any] = {
        "strictness": int(p.get("strictness", 0)),
        "allow_public_access_points": _bool_str(
            p.get("allow_public_access_points", True)
        ),
        "lighter_penalties": _bool_str(p.get("lighter_penalties", False)),
        "fast": _bool_str(p.get("fast", False)),
    }

    if p.get("mobile") is not None:
        params["mobile"] = _bool_str(p["mobile"])
    if p.get("user_agent"):
        params["user_agent"] = str(p["user_agent"])
    if p.get("user_language"):
        params["user_language"] = str(p["user_language"])
    if p.get("transaction_strictness") is not None:
        params["transaction_strictness"] = int(p["transaction_strictness"])

    for key, value in (CONFIG.get("request_fields") or {}).items():
        params[str(key)] = value

    for key, value in (CONFIG.get("custom_variables") or {}).items():
        params[str(key)] = str(value)

    return params


def _retry_after_seconds(headers: Any) -> Optional[float]:
    if headers is None:
        return None
    value = headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def _api_error_properties(message: str) -> Tuple[bool, bool]:
    low = message.lower()

    fatal_markers = (
        "insufficient credits",
        "invalid api key",
        "invalid or unauthorized",
        "unauthorized",
        "access denied",
        "account disabled",
    )
    retry_markers = (
        "rate limit",
        "too many requests",
        "temporarily unavailable",
        "try again",
        "timeout",
        "service unavailable",
        "internal server error",
        "bad gateway",
        "gateway timeout",
    )

    fatal = any(marker in low for marker in fatal_markers)
    retryable = any(marker in low for marker in retry_markers)
    return retryable, fatal


def _make_request(
    url: str,
    method: str,
    params: Dict[str, Any],
    api_key: str,
    timeout: float,
) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    method = method.upper()
    headers = {
        "User-Agent": f"IPQS-Lookup/{__version__} (Python)",
        "Accept": "application/json",
        "Connection": "close",
    }

    if CONFIG.get("key_in_header", True):
        headers["IPQS-KEY"] = api_key

    if method == "POST":
        body = urllib.parse.urlencode(
            params, doseq=True, quote_via=urllib.parse.quote
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                **headers,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
    else:
        query = urllib.parse.urlencode(params, doseq=True, quote_via=urllib.parse.quote)
        separator = "&" if "?" in url else "?"
        request = urllib.request.Request(
            f"{url}{separator}{query}",
            headers=headers,
            method="GET",
        )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            headers_out = {k: v for k, v in response.headers.items()}
            status = int(getattr(response, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        retry_after = _retry_after_seconds(exc.headers)
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        message = f"HTTP {exc.code} {exc.reason}"
        if raw:
            try:
                parsed_error = json.loads(raw)
                if isinstance(parsed_error, dict):
                    message = str(parsed_error.get("message") or message)
            except ValueError:
                pass

        retryable = exc.code in (408, 425, 429) or exc.code >= 500
        raise IPQSError(message, retryable=retryable, retry_after=retry_after) from None
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise IPQSError("Request timed out", retryable=True) from None
        raise IPQSError(f"Network error: {exc.reason}", retryable=True) from None
    except (socket.timeout, TimeoutError):
        raise IPQSError("Request timed out", retryable=True) from None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IPQSError(
            f"Failed to parse JSON response: {exc}", retryable=True
        ) from None

    if not isinstance(data, dict):
        raise IPQSError("Unexpected response shape from API")

    if data.get("success") is False:
        message = str(data.get("message") or "Unknown API error")
        retryable, fatal = _api_error_properties(message)
        raise IPQSError(message, retryable=retryable, fatal=fatal)

    return status, data, headers_out


def request_once(
    ip: str,
    params: Dict[str, Any],
    api_key: str,
    timeout: float,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    api_url = os.environ.get("IPQS_API_URL") or CONFIG.get("api_url") or API_URL_DEFAULT
    if not api_url:
        raise IPQSError("No IPQS API URL configured", fatal=True)

    method = str(CONFIG.get("method", "POST")).upper()
    if method not in {"GET", "POST"}:
        raise IPQSError(f"Unsupported HTTP method: {method}", fatal=True)

    request_params = dict(params)

    if method == "GET" and not CONFIG.get("key_in_header", True):
        # Classic key-in-path URL style.
        url = (
            f"{api_url.rstrip('/')}/{urllib.parse.quote(api_key, safe='')}/"
            f"{urllib.parse.quote(ip, safe='')}"
        )
    else:
        url = api_url
        request_params["ip"] = ip

    started = time.monotonic()
    status, data, _headers = _make_request(
        url=url,
        method=method,
        params=request_params,
        api_key=api_key,
        timeout=timeout,
    )
    elapsed_ms = (time.monotonic() - started) * 1000.0

    meta = {
        "http_status": status,
        "elapsed_ms": round(elapsed_ms, 2),
        "method": method,
    }
    return data, meta


def lookup_ip(
    ip: str,
    params: Dict[str, Any],
    api_key: str,
    limiter: RateLimiter,
    abort: threading.Event,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    net = CONFIG["network"]
    retries = max(0, int(net.get("retries", 4)))
    base = max(0.0, float(net.get("backoff", 1.0)))
    max_backoff = max(base, float(net.get("max_backoff", 30.0)))
    timeout = max(0.1, float(net.get("timeout", 20.0)))

    for attempt in range(retries + 1):
        if abort.is_set():
            raise IPQSError("skipped (run aborted)")

        limiter.wait()
        try:
            return request_once(ip, params, api_key, timeout)
        except IPQSError as exc:
            if exc.fatal:
                abort.set()
                raise
            if not exc.retryable or attempt >= retries:
                raise

            delay = exc.retry_after
            if delay is None:
                delay = min(max_backoff, base * (2**attempt))
                jitter = min(0.5, base / 2 if base else 0.1)
                delay += random.uniform(0.0, jitter)
            else:
                delay = min(max_backoff, delay)

            time.sleep(max(0.0, delay))

    raise IPQSError("unreachable")  # pragma: no cover


# ============================================================================
# ANALYSIS
# ============================================================================
def normalize_events(raw: Any) -> List[Dict[str, Any]]:
    """abuse_events can arrive in a few shapes; flatten to [{name, last_seen}]."""
    if isinstance(raw, dict):
        if "name" in raw:
            raw = [raw]
        else:
            lists = [v for v in raw.values() if isinstance(v, list)]
            if lists:
                raw = [e for lst in lists for e in lst]
            else:
                raw = [
                    {"name": k, "last_seen": v}
                    for k, v in raw.items()
                    if isinstance(v, (str, type(None)))
                ]

    events: List[Dict[str, Any]] = []
    if isinstance(raw, list):
        for e in raw:
            if isinstance(e, dict) and e.get("name"):
                events.append({"name": str(e["name"]), "last_seen": e.get("last_seen")})
            elif isinstance(e, str):
                events.append({"name": e, "last_seen": None})
    return events


def as_bool(data: Dict[str, Any], key: str) -> Optional[bool]:
    value = data.get(key)
    return value if isinstance(value, bool) else None


def fraud_score_class(score: Any) -> str:
    """
    IPQS-oriented classification using documented bands:
      <75    = lower risk
      75-89  = suspicious
      >=90   = high risk / recommended block threshold
    """
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        if score >= 90:
            return "HIGH RISK"
        if score >= 75:
            return "SUSPICIOUS"
        return "CLEAN"
    return "UNKNOWN"


def fraud_tier(score: Any) -> Tuple[str, str]:
    """(label, colour) using IPQS's documented 75 / 85 / 90 bands."""
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return "n/a", C.GREY
    if score >= 90:
        return "HIGH RISK - recommended block threshold", C.RED
    if score >= 85:
        return "high risk", C.RED
    if score >= 75:
        return "suspicious", C.YELLOW
    return "low risk", C.GREEN


def score_bar(score: Any, width: int = 20) -> str:
    if not isinstance(score, (int, float)) or isinstance(score, bool):
        return paint("n/a", C.GREY)
    label, col = fraud_tier(score)
    filled = round(width * min(max(float(score), 0), 100) / 100)
    return (
        f"{paint('█' * filled + '░' * (width - filled), col)} "
        f"{score:g}  {paint(label, col)}"
    )


def local_evidence_score(
    data: Dict[str, Any],
) -> Tuple[int, List[Dict[str, Any]], List[str], List[str]]:
    """
    Compute the tool's local evidence score (0-100) and its supporting
    signals, tags, and notes. Deliberately separate from IPQS's fraud_score.
    """
    W = CONFIG["local_weights"]
    signals: List[Dict[str, Any]] = []
    tags: List[str] = []
    notes: List[str] = []

    def add(name: str, points: int, detail: str = "") -> None:
        if points:
            signals.append({"signal": name, "points": int(points), "detail": detail})

    def tag(value: str) -> None:
        if value and value not in tags:
            tags.append(value)

    # --- Anonymisers ---------------------------------------------------
    if as_bool(data, "active_tor"):
        tag("ACTIVE-TOR")
        add("active_tor", int(W["active_tor"]), "active Tor exit node")
    elif as_bool(data, "tor"):
        tag("TOR")
        add("tor", int(W["tor"]), "suspected / previously active Tor node")

    if as_bool(data, "active_vpn"):
        tag("ACTIVE-VPN")
        add(
            "active_vpn",
            int(W["active_vpn"]),
            "active VPN (popular service or private server)",
        )
    elif as_bool(data, "vpn"):
        tag("VPN")
        add("vpn", int(W["vpn"]), "suspected VPN (may include dormant DC ranges)")

    if as_bool(data, "proxy"):
        tag("PROXY")
        # IPQS documents vpn/tor as implying proxy=true; avoid double counting.
        if not (
            as_bool(data, "vpn")
            or as_bool(data, "active_vpn")
            or as_bool(data, "tor")
            or as_bool(data, "active_tor")
        ):
            add("proxy", int(W["proxy"]), "suspected proxy (SOCKS / elite / anon)")

    # --- Automation & abuse -------------------------------------------
    if as_bool(data, "bot_status"):
        tag("BOT")
        add(
            "bot_status",
            int(W["bot_status"]),
            "recent automated / non-human fraud activity",
        )

    if as_bool(data, "is_crawler"):
        tag("CRAWLER")
        notes.append(
            "Verified search-engine crawler (Google/Bing/etc.) - normally legitimate."
        )
        add("is_crawler", int(W["is_crawler"]), "verified search-engine crawler")

    if as_bool(data, "security_scanner"):
        tag("SCANNER")
        notes.append("Verified security scanner (Tenable/Qualys-style vendor).")
        add("security_scanner", int(W["security_scanner"]), "verified security scanner")

    if as_bool(data, "recent_abuse"):
        tag("RECENT-ABUSE")
        add(
            "recent_abuse",
            int(W["recent_abuse"]),
            "verified abuse across the IPQS network in the past few days",
        )

    if as_bool(data, "frequent_abuser"):
        tag("FREQUENT-ABUSER")
        add(
            "frequent_abuser",
            int(W["frequent_abuser"]),
            "abusive history spanning 6+ months",
        )

    if as_bool(data, "high_risk_attacks"):
        tag("HIGH-RISK-ATTACKS")
        add(
            "high_risk_attacks",
            int(W["high_risk_attacks"]),
            "phishing / brute force / DDoS / credential stuffing / scraping / spam",
        )

    velocity = str(data.get("abuse_velocity") or "").strip().lower()
    velocity_weights = W.get("abuse_velocity", {})
    if velocity in velocity_weights:
        add("abuse_velocity", int(velocity_weights[velocity]), velocity)

    events = normalize_events(data.get("abuse_events"))
    if events:
        names = sorted({event["name"] for event in events})
        points = min(int(W["abuse_event_cap"]), int(W["abuse_event"]) * len(names))
        add("abuse_events", points, ", ".join(names))

    # --- Network context ----------------------------------------------
    ctype = str(data.get("connection_type") or "").strip()
    if ctype and ctype.upper() != "N/A":
        normalized = re.sub(r"[^A-Za-z]", "", ctype).lower()
        if normalized == "datacenter":
            tag("DATACENTER")
            add("data_center", int(W["data_center"]), "hosting / data-centre range")
        else:
            tag(ctype.upper().replace(" ", "-"))

    if as_bool(data, "shared_connection"):
        tag("SHARED")
        notes.append(
            "Shared connection - many users may sit behind this IP; "
            "blocking it risks collateral damage."
        )

    if as_bool(data, "dynamic_connection"):
        tag("DYNAMIC")
        notes.append("Dynamic IP - likely to be reassigned to a different user soon.")

    if as_bool(data, "trusted_network"):
        tag("TRUSTED")
        add(
            "trusted_network",
            int(W["trusted_network"]),
            "low-abuse corporate network",
        )

    missing = [field for field in ENTERPRISE_FLAGS if field not in data]
    if missing:
        notes.append(
            "Not returned (enterprise data points, may need a higher plan): "
            + ", ".join(missing)
        )

    # --- Transaction risk ---------------------------------------------
    transaction = data.get("transaction_details")
    if isinstance(transaction, dict):
        tx_weight = float(W.get("transaction_risk_multiplier", 1.0))
        raw_risk = transaction.get("risk_score")
        if isinstance(raw_risk, (int, float)) and not isinstance(raw_risk, bool):
            if raw_risk >= 90:
                add(
                    "transaction_risk",
                    int(round(35 * tx_weight)),
                    f"transaction risk_score={raw_risk:g}",
                )
            elif raw_risk >= 75:
                add(
                    "transaction_risk",
                    int(round(20 * tx_weight)),
                    f"transaction risk_score={raw_risk:g}",
                )

        if transaction.get("fraudulent_behavior") is True:
            add(
                "transaction_fraudulent_behavior",
                int(round(35 * tx_weight)),
                "IPQS transaction_details.fraudulent_behavior=true",
            )

    # --- Premium reasons ----------------------------------------------
    reasons = data.get("reasons")
    if isinstance(reasons, list) and reasons:
        notes.append("Fraud score reasons: " + "; ".join(str(r) for r in reasons))

    total = max(0, min(100, sum(item["points"] for item in signals)))
    return total, signals, tags, notes


def analyze(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a two-layer analysis dict:

      - verdict           : tool's local verdict (evidence-based)
      - ipqs_verdict      : IPQS official fraud_score classification
      - risk_points       : final combined 0-100 score (max of the two)
      - fraud_score       : raw IPQS fraud_score
      - evidence_score    : local evidence score
      - signals/tags/notes: supporting detail
    """
    evidence_score, signals, tags, notes = local_evidence_score(data)

    fraud_score = data.get("fraud_score")
    ipqs_class = fraud_score_class(fraud_score)

    thresholds = CONFIG["local_verdicts"]

    if isinstance(fraud_score, (int, float)) and not isinstance(fraud_score, bool):
        # IPQS's fraud_score is the primary measure. Local evidence can only
        # elevate the verdict when it independently crosses our thresholds.
        primary_points = int(round(max(0, min(100, float(fraud_score)))))
        risk_points = max(primary_points, evidence_score)

        if risk_points >= thresholds["high_risk"]:
            local_verdict = "HIGH RISK"
        elif risk_points >= thresholds["suspicious"]:
            local_verdict = "SUSPICIOUS"
        elif risk_points >= thresholds["caution"]:
            local_verdict = "CAUTION"
        else:
            local_verdict = "CLEAN"

        if evidence_score > primary_points:
            notes.append(
                f"Local evidence score ({evidence_score}) elevated the tool "
                f"verdict above the IPQS Fraud Score ({primary_points})."
            )
    else:
        risk_points = evidence_score
        if risk_points >= thresholds["high_risk"]:
            local_verdict = "HIGH RISK"
        elif risk_points >= thresholds["suspicious"]:
            local_verdict = "SUSPICIOUS"
        elif risk_points >= thresholds["caution"]:
            local_verdict = "CAUTION"
        else:
            local_verdict = "CLEAN"
        notes.append("No fraud_score returned; local evidence scoring is being used.")

    transaction = data.get("transaction_details")
    tx_score = transaction.get("risk_score") if isinstance(transaction, dict) else None

    return {
        "verdict": local_verdict,
        "risk_points": risk_points,
        "ipqs_verdict": ipqs_class,
        "fraud_score": fraud_score,
        "evidence_score": evidence_score,
        "transaction_risk_score": tx_score,
        "signals": signals,
        "tags": tags,
        "notes": notes,
        "abuse_events": normalize_events(data.get("abuse_events")),
        "reasons": data.get("reasons") if isinstance(data.get("reasons"), list) else [],
    }


# ============================================================================
# REDACTION
# ============================================================================
def redact_value(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            k: redact_value(v, str(k))
            for k, v in value.items()
            if not SENSITIVE_FIELD_RE.search(str(k))
        }
    if isinstance(value, list):
        return [redact_value(v, key) for v in value]
    if SENSITIVE_FIELD_RE.search(key):
        return "[REDACTED]"
    return value


def output_data(data: Dict[str, Any], redact: bool) -> Dict[str, Any]:
    return redact_value(data) if redact else data


# ============================================================================
# OUTPUT: BOOL/BOOL HELPERS
# ============================================================================
def fmt_bool(value: Optional[bool], kind: str = "bad") -> str:
    if value is None:
        return paint("n/a", C.GREY)
    if kind == "bad":
        return paint("YES", C.RED) if value else paint("no", C.GREEN)
    if kind == "good":
        return paint("YES", C.GREEN) if value else paint("no", C.GREY)
    return paint("YES", C.YELLOW) if value else paint("no", C.GREY)


def val(data: Dict[str, Any], *keys: str, default: Any = "?") -> Any:
    for k in keys:
        if k in data and data[k] not in (None, ""):
            return data[k]
    return default


# ============================================================================
# OUTPUT: VERBOSE
# ============================================================================
WIDTH = 80


def print_verbose(result: Dict[str, Any], redact: bool = False) -> None:
    data = result["data"]
    analysis = result["analysis"]
    ip = result["ip"]

    def flag(key: str) -> Optional[bool]:
        return as_bool(data, key)

    def row(label: str, value: Any) -> None:
        print(f"  {paint(label.ljust(24), C.CYAN)} {value}")

    def section(title: str) -> None:
        print()
        print(paint(f"  {title}", C.BOLD))
        print(paint("  " + "-" * (WIDTH - 4), C.GREY))

    head = (
        f"{paint('IP:', C.BOLD)} {ip}   "
        f"{paint('VERDICT:', C.BOLD)} "
        f"{paint(analysis['verdict'], VERDICT_COLORS[analysis['verdict']])}   "
        f"{paint('RISK:', C.BOLD)} {analysis['risk_points']}/100"
    )
    if result.get("cached"):
        head += paint("   (cached)", C.GREY)

    print()
    print(paint("=" * WIDTH, C.GREY))
    print(head)
    print(
        f"{paint('IPQS:', C.BOLD)} {analysis['ipqs_verdict']}   "
        f"{paint('EVIDENCE:', C.BOLD)} {analysis['evidence_score']}/100"
        + (
            f"   {paint('TRANSACTION:', C.BOLD)} "
            f"{analysis['transaction_risk_score']}/100"
            if analysis.get("transaction_risk_score") is not None
            else ""
        )
    )
    if analysis["tags"]:
        print(
            f"{paint('TAGS:', C.BOLD)} "
            + " ".join(paint(f"[{t}]", tag_color(t)) for t in analysis["tags"])
        )
    print(paint("=" * WIDTH, C.GREY))

    section("RISK")
    row("Fraud Score", score_bar(data.get("fraud_score")))
    row("IPQS Classification", analysis["ipqs_verdict"])
    row("Local Evidence Score", f"{analysis['evidence_score']}/100")
    velocity = data.get("abuse_velocity")
    vcol = {"high": C.RED, "medium": C.YELLOW, "low": C.CYAN}.get(
        str(velocity).lower(), C.GREEN
    )
    row(
        "Abuse Velocity",
        paint(str(velocity), vcol) if velocity else paint("n/a", C.GREY),
    )
    row("Recent Abuse", fmt_bool(flag("recent_abuse")))
    row("Frequent Abuser", fmt_bool(flag("frequent_abuser")))
    row("High-Risk Attacks", fmt_bool(flag("high_risk_attacks")))

    section("ANONYMISATION")
    row("Proxy", fmt_bool(flag("proxy")))
    row("VPN (suspected)", fmt_bool(flag("vpn")))
    row("VPN (active)", fmt_bool(flag("active_vpn")))
    row("Tor (suspected)", fmt_bool(flag("tor")))
    row("Tor (active exit)", fmt_bool(flag("active_tor")))

    section("AUTOMATION")
    row("Bot Activity", fmt_bool(flag("bot_status")))
    row("Verified Crawler", fmt_bool(flag("is_crawler"), "info"))
    row("Security Scanner", fmt_bool(flag("security_scanner"), "info"))

    section("NETWORK TRUST")
    row("Connection Type", val(data, "connection_type"))
    row("Mobile", fmt_bool(flag("mobile"), "info"))
    row("Public Access Point", fmt_bool(flag("public_access_point"), "info"))
    row("Shared Connection", fmt_bool(flag("shared_connection"), "info"))
    row("Dynamic IP", fmt_bool(flag("dynamic_connection"), "info"))
    row("Trusted Network", fmt_bool(flag("trusted_network"), "good"))

    section("LOCATION / OWNER")
    row("Country", val(data, "country_code"))
    row("Region", val(data, "region"))
    row("City", val(data, "city"))
    row("Postal Code", val(data, "zip_code"))
    lat, lon = data.get("latitude"), data.get("longitude")
    row(
        "Coordinates",
        f"{lat}, {lon}" if lat is not None and lon is not None else "?",
    )
    row("Timezone", val(data, "timezone"))
    row("ISP", val(data, "ISP"))
    row("Organization", val(data, "organization", "Organization"))
    row("ASN", val(data, "ASN"))
    row("Hostname", val(data, "host"))

    if any(
        data.get(k) not in (None, "", "N/A")
        for k in ("operating_system", "browser", "device_brand", "device_model")
    ):
        section("DEVICE (from user agent)")
        row("Operating System", val(data, "operating_system"))
        row("Browser", val(data, "browser"))
        row("Device Brand", val(data, "device_brand"))
        row("Device Model", val(data, "device_model"))

    # Device fingerprinting fields (if present)
    device_extras = {k: data[k] for k in DEVICE_FIELDS if k in data}
    if device_extras:
        section("DEVICE FINGERPRINTING")
        for k, v in device_extras.items():
            row(str(k), redact_value(v, str(k)) if redact else v)

    events = analysis["abuse_events"]
    if events:
        section("ABUSE EVENTS")
        for event in sorted(
            events,
            key=lambda x: str(x.get("last_seen") or ""),
            reverse=True,
        ):
            row(
                event["name"],
                paint(f"last seen {event.get('last_seen') or '?'}", C.YELLOW),
            )

    transaction = data.get("transaction_details")
    if isinstance(transaction, dict):
        section("TRANSACTION DETAILS")
        tx = redact_value(transaction) if redact else transaction
        for key in sorted(tx):
            value = tx[key]
            if isinstance(value, (dict, list)):
                value = pretty_json(value)
            row(str(key), value)

    for key in ("recent_data_matches", "recent_unique_user_values"):
        if key in data:
            section(key.replace("_", " ").upper())
            value = redact_value(data[key]) if redact else data[key]
            print("  " + pretty_json(value).replace("\n", "\n  "))

    if analysis["signals"]:
        section("WHY THIS TOOL VERDICT")
        for signal in analysis["signals"]:
            points = signal["points"]
            color = C.RED if points > 0 else C.GREEN
            print(
                f"  {paint(f'{points:+d}'.rjust(4), color)}  "
                f"{signal['signal'].ljust(28)} "
                f"{paint(signal['detail'], C.GREY)}"
            )

    if analysis["notes"]:
        section("NOTES")
        for note in analysis["notes"]:
            print(f"  - {note}")

    # Fraud score reasons (premium)
    reasons = analysis.get("reasons") or []
    if reasons:
        section("FRAUD SCORE REASONS (premium)")
        for reason in reasons:
            print(f"  {paint('•', C.YELLOW)} {reason}")

    extras = {k: v for k, v in data.items() if k not in KNOWN_FIELDS}
    if extras:
        section("ADDITIONAL DATA")
        for key, value in extras.items():
            display = redact_value(value, str(key)) if redact else value
            row(
                str(key),
                pretty_json(display) if isinstance(display, (dict, list)) else display,
            )

    if data.get("errors"):
        section("API ERRORS")
        for error in data["errors"]:
            print(f"  {paint(str(error), C.RED)}")

    section("REQUEST")
    row("Method", result.get("method", "?"))
    row("HTTP Status", result.get("http_status", "?"))
    row("Response Time", f"{result.get('elapsed_ms', '?')} ms")
    row("Request ID", data.get("request_id") or "?")

    print()


# ============================================================================
# OUTPUT: COMPACT
# ============================================================================
def print_compact(result: Dict[str, Any]) -> None:
    data, analysis = result["data"], result["analysis"]
    tx = ""
    transaction = data.get("transaction_details")
    if isinstance(transaction, dict) and transaction.get("risk_score") is not None:
        tx = str(transaction["risk_score"])
    print(
        f"{result['ip']}\t"
        f"{analysis['verdict']}\t"
        f"{analysis['risk_points']}\t"
        f"{analysis['ipqs_verdict']}\t"
        f"{data.get('fraud_score', '?')}\t"
        f"{analysis['evidence_score']}\t"
        f"{tx}\t"
        f"{','.join(analysis['tags']) or '-'}"
    )


# ============================================================================
# OUTPUT: SUMMARY TABLE
# ============================================================================
def print_summary_table(results: Sequence[Dict[str, Any]]) -> None:
    ok = [r for r in results if not r.get("error")]
    if not ok:
        return

    ipw = max(len(r["ip"]) for r in ok) + 2
    total = ipw + 14 + 7 + 10 + 8 + 7 + 6 + 26

    print()
    print(paint("SUMMARY", C.BOLD))
    print(paint("-" * total, C.GREY))
    header = (
        "IP".ljust(ipw)
        + "VERDICT".ljust(14)
        + "RISK".ljust(7)
        + "IPQS".ljust(10)
        + "FRAUD".ljust(8)
        + "EVID".ljust(7)
        + "TX".ljust(6)
        + "TAGS"
    )
    print(paint(header, C.BOLD))
    print(paint("-" * total, C.GREY))

    for result in ok:
        analysis, data = result["analysis"], result["data"]
        tags = ",".join(analysis["tags"]) or "-"
        if len(tags) > 26:
            tags = tags[:23] + "..."

        tx = ""
        transaction = data.get("transaction_details")
        if isinstance(transaction, dict) and transaction.get("risk_score") is not None:
            tx = str(transaction["risk_score"])

        print(
            result["ip"].ljust(ipw)
            + pad(analysis["verdict"], 14, VERDICT_COLORS[analysis["verdict"]])
            + str(analysis["risk_points"]).ljust(7)
            + str(analysis["ipqs_verdict"]).ljust(10)
            + str(data.get("fraud_score", "?")).ljust(8)
            + str(analysis["evidence_score"]).ljust(7)
            + tx.ljust(6)
            + tags
        )
    print()


# ============================================================================
# OUTPUT: PRIORITISED RISK REPORT
# ============================================================================
def print_risk_report(results: Sequence[Dict[str, Any]]) -> None:
    ranked = [r for r in results if r.get("analysis") and not r.get("error")]
    if not ranked:
        return

    def sort_key(result: Dict[str, Any]) -> Tuple[int, int, float]:
        analysis = result["analysis"]
        score = result["data"].get("fraud_score")
        score = (
            float(score)
            if isinstance(score, (int, float)) and not isinstance(score, bool)
            else 0.0
        )
        return (
            VERDICT_RANK.get(analysis["verdict"], 0),
            int(analysis["risk_points"]),
            score,
        )

    ranked.sort(key=sort_key, reverse=True)
    ipw = max(12, max(len(r["ip"]) for r in ranked) + 2)

    print()
    print(paint("PRIORITISED RISK REPORT", C.BOLD))
    print(paint("=" * (ipw + 76), C.GREY))
    print(
        "#".ljust(4)
        + "IP".ljust(ipw)
        + "VERDICT".ljust(14)
        + "RISK".ljust(7)
        + "IPQS".ljust(10)
        + "FRAUD".ljust(8)
        + "EVID".ljust(7)
        + "VELOCITY".ljust(10)
        + "TAGS"
    )
    print(paint("-" * (ipw + 76), C.GREY))

    for rank, result in enumerate(ranked, 1):
        analysis, data = result["analysis"], result["data"]
        tags = ",".join(analysis["tags"]) or "-"
        if len(tags) > 40:
            tags = tags[:37] + "..."
        velocity = str(data.get("abuse_velocity") or "-")
        vcol = {"high": C.RED, "medium": C.YELLOW}.get(velocity.lower(), C.GREY)
        print(
            f"{str(rank) + '.':<4}"
            f"{result['ip'].ljust(ipw)}"
            f"{pad(analysis['verdict'], 14, VERDICT_COLORS[analysis['verdict']])}"
            f"{str(analysis['risk_points']).ljust(7)}"
            f"{str(analysis['ipqs_verdict']).ljust(10)}"
            f"{str(data.get('fraud_score', '?')).ljust(8)}"
            f"{str(analysis['evidence_score']).ljust(7)}"
            f"{paint(velocity.ljust(10), vcol)}"
            f"{tags}"
        )

    counts = {
        verdict: sum(1 for result in ranked if result["analysis"]["verdict"] == verdict)
        for verdict in VERDICT_ORDER
    }
    breakdown = "  ".join(f"{v}: {n}" for v, n in counts.items() if n)
    print(paint("-" * (ipw + 76), C.GREY))
    print(paint(f"  Totals: {breakdown}", C.BOLD))
    print()


# ============================================================================
# OUTPUT: CSV / JSON
# ============================================================================
def build_row(result: Dict[str, Any], redact: bool = False) -> Dict[str, Any]:
    """Flatten one result into a row suitable for CSV/JSON filtering."""
    data = output_data(result.get("data") or {}, redact)
    analysis = result.get("analysis")

    row: Dict[str, Any] = {field: data.get(field, "") for field in CSV_FIELDS}
    row["organization"] = val(data, "organization", "Organization", default="")

    if isinstance(analysis, dict):
        row.update(
            {
                "ip": result["ip"],
                "verdict": analysis["verdict"],
                "ipqs_verdict": analysis["ipqs_verdict"],
                "risk_points": analysis["risk_points"],
                "fraud_score": analysis.get("fraud_score", ""),
                "evidence_score": analysis["evidence_score"],
                "transaction_risk_score": analysis.get("transaction_risk_score", ""),
                "tags": ";".join(analysis["tags"]),
                "signals": ";".join(
                    f"{item['signal']}({item['points']:+d})"
                    for item in analysis["signals"]
                ),
                "reasons": ";".join(analysis.get("reasons") or []),
                "abuse_events": ";".join(
                    f"{event['name']}@{event.get('last_seen') or '?'}"
                    for event in analysis["abuse_events"]
                ),
            }
        )
    else:
        row.update(
            {
                "ip": result["ip"],
                "verdict": "ERROR",
                "ipqs_verdict": "",
                "risk_points": "",
                "fraud_score": "",
                "evidence_score": "",
                "transaction_risk_score": "",
                "tags": "",
                "signals": "",
                "reasons": "",
                "abuse_events": "",
            }
        )

    row["request_id"] = data.get("request_id", "")
    row["method"] = result.get("method", "")
    row["http_status"] = result.get("http_status", "")
    row["elapsed_ms"] = result.get("elapsed_ms", "")
    row["cached"] = result.get("cached", False)
    row["error"] = result.get("error") or ""
    return row


def write_csv(
    path: str,
    results: Sequence[Dict[str, Any]],
    fields: Optional[Sequence[str]] = None,
    redact: bool = False,
    no_header: bool = False,
) -> None:
    fieldnames = list(fields) if fields else list(CSV_FIELDS)
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        if not no_header:
            writer.writeheader()
        for result in results:
            row = build_row(result, redact=redact)
            writer.writerow({k: row.get(k, "") for k in fieldnames})


def result_to_json(
    result: Dict[str, Any],
    redact: bool = False,
    fields: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    analysis = result.get("analysis")

    if fields:
        # Flat filtered output: only the requested fields.
        flat = build_row(result, redact=redact)
        return {k: flat.get(k, "") for k in fields}

    return {
        "ip": result["ip"],
        "verdict": analysis["verdict"] if analysis else "ERROR",
        "ipqs_verdict": analysis["ipqs_verdict"] if analysis else "UNKNOWN",
        "risk_points": analysis["risk_points"] if analysis else None,
        "fraud_score": analysis.get("fraud_score") if analysis else None,
        "evidence_score": analysis.get("evidence_score") if analysis else None,
        "transaction_risk_score": (
            analysis.get("transaction_risk_score") if analysis else None
        ),
        "tags": analysis["tags"] if analysis else [],
        "signals": analysis["signals"] if analysis else [],
        "notes": analysis["notes"] if analysis else [],
        "reasons": analysis.get("reasons", []) if analysis else [],
        "cached": bool(result.get("cached")),
        "method": result.get("method"),
        "http_status": result.get("http_status"),
        "elapsed_ms": result.get("elapsed_ms"),
        "error": result.get("error"),
        "data": output_data(result.get("data", {}), redact),
    }


# ============================================================================
# INPUT HANDLING
# ============================================================================
def split_tokens(text: str) -> List[str]:
    """One or more IPs per line; '#' starts a comment; commas/whitespace separate."""
    out: List[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        out.extend(token for token in re.split(r"[\s,;]+", line) if token)
    return out


def read_ips_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8-sig") as handle:
        return split_tokens(handle.read())


def read_ips_from_stdin() -> List[str]:
    return split_tokens(sys.stdin.read())


# ============================================================================
# WORKER
# ============================================================================
def process_ip(
    ip: str,
    params: Dict[str, Any],
    api_key: str,
    cache: Cache,
    limiter: RateLimiter,
    abort: threading.Event,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ip": ip,
        "data": {},
        "analysis": None,
        "cached": False,
        "error": None,
        "method": str(CONFIG.get("method", "POST")).upper(),
        "http_status": None,
        "elapsed_ms": None,
    }

    sensitive = request_contains_sensitive_fields(params)
    key = Cache.key(ip, params)

    try:
        data = cache.get(key, sensitive=sensitive)
        if data is not None:
            result["cached"] = True
        else:
            data, meta = lookup_ip(ip, params, api_key, limiter, abort)
            result.update(meta)
            cache.put(key, data, sensitive=sensitive)

        result["data"] = data
        result["analysis"] = analyze(data)
    except IPQSError as exc:
        result["error"] = str(exc)
        result["retryable"] = exc.retryable
        result["fatal"] = exc.fatal
    except Exception as exc:  # never let one IP kill the batch
        result["error"] = f"Unexpected error: {type(exc).__name__}: {exc}"

    return result


# ============================================================================
# POSTBACK API (optional)
# ============================================================================
def postback_lookup(
    request_id: str,
    api_key: str,
    vars: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Retrieve a past lookup via the IPQS Postback API.

    Endpoint format:
      https://www.ipqualityscore.com/api/json/postback/{API_KEY}/{REQUEST_ID}
    """
    url = (
        f"https://www.ipqualityscore.com/api/json/postback/"
        f"{urllib.parse.quote(api_key, safe='')}/"
        f"{urllib.parse.quote(request_id, safe='')}"
    )
    params: Dict[str, str] = {"type": "proxy"}
    if vars:
        params.update(vars)
    full = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(full, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


# ============================================================================
# SELF TEST
# ============================================================================
def run_self_test() -> int:
    samples = [
        (
            "clean",
            {
                "success": True,
                "fraud_score": 12,
                "proxy": False,
                "vpn": False,
                "tor": False,
                "bot_status": False,
                "recent_abuse": False,
                "abuse_velocity": "none",
                "connection_type": "Residential",
            },
            "CLEAN",
        ),
        (
            "vpn-suspicious",
            {
                "success": True,
                "fraud_score": 81,
                "proxy": True,
                "vpn": True,
                "active_vpn": True,
                "tor": False,
                "bot_status": False,
                "recent_abuse": False,
                "abuse_velocity": "none",
                "connection_type": "Data Center",
            },
            "SUSPICIOUS",
        ),
        (
            "high-risk-abuse",
            {
                "success": True,
                "fraud_score": 94,
                "proxy": True,
                "vpn": False,
                "tor": False,
                "active_tor": False,
                "bot_status": True,
                "recent_abuse": True,
                "frequent_abuser": True,
                "high_risk_attacks": True,
                "abuse_velocity": "high",
                "connection_type": "Data Center",
                "abuse_events": [
                    {
                        "name": "Brute Force Attacks",
                        "last_seen": "2026-09-01T10:00:00Z",
                    },
                    {"name": "Bot Attacks", "last_seen": "2026-09-01T11:00:00Z"},
                ],
                "transaction_details": {
                    "risk_score": 97,
                    "fraudulent_behavior": True,
                },
                "reasons": ["IP is on a datacenter range", "Recent abuse detected"],
            },
            "HIGH RISK",
        ),
        (
            "missing-fraud-score",
            {
                "success": True,
                "proxy": True,
                "active_tor": True,
                "recent_abuse": True,
                "abuse_velocity": "high",
            },
            "HIGH RISK",
        ),
        (
            "tx-risk-only",
            {
                "success": True,
                "fraud_score": 20,
                "proxy": False,
                "vpn": False,
                "tor": False,
                "bot_status": False,
                "recent_abuse": False,
                "transaction_details": {
                    "risk_score": 95,
                    "fraudulent_behavior": False,
                },
            },
            # fraud_score=20 (CLEAN primary) but evidence gets +35 for tx risk,
            # which pushes evidence >= high_risk threshold (90)?  Actually 35,
            # so it lands at CAUTION range in local_verdicts.  High risk only
            # if combined >= 90.  So expected: CLEAN (since risk_points = max(20,35)=35).
            # I keep this test to prove no false HIGH-RISK elevation.
            "CLEAN",
        ),
    ]

    print(f"IPQS Lookup {__version__} self-test")
    failures = 0
    for name, data, expected in samples:
        analysis = analyze(data)
        ok = analysis["verdict"] == expected
        print(
            f"  {'PASS' if ok else 'FAIL':<4} {name:<24} "
            f"verdict={analysis['verdict']:<10} "
            f"ipqs={analysis['ipqs_verdict']:<10} "
            f"evidence={analysis['evidence_score']}"
        )
        if not ok:
            failures += 1

    sensitive = request_contains_sensitive_fields(
        {"billing_phone": "123", "strictness": 0}
    )
    nonsensitive = request_contains_sensitive_fields({"strictness": 0, "fast": True})
    cache_key_a = Cache.key("1.2.3.4", {"a": 1, "b": 2})
    cache_key_b = Cache.key("1.2.3.4", {"b": 2, "a": 1})

    checks = [
        ("sensitive-cache-detection", sensitive),
        ("normal-cache-detection", not nonsensitive),
        ("stable-cache-key", cache_key_a == cache_key_b),
        ("fraud-score-class-high", fraud_score_class(95) == "HIGH RISK"),
        ("fraud-score-class-susp", fraud_score_class(80) == "SUSPICIOUS"),
        ("fraud-score-class-clean", fraud_score_class(30) == "CLEAN"),
        (
            "field-filter-preserves-order",
            resolve_fields(["a,b"], ["b", "a"]) == ["a", "b"],
        ),
        (
            "field-filter-empty-defaults",
            resolve_fields(None, ["a", "b"]) == ["a", "b"],
        ),
    ]
    for label, value in checks:
        print(f"  {'PASS' if value else 'FAIL':<4} {label}")
        if not value:
            failures += 1

    print(f"\nResult: {'PASS' if failures == 0 else f'{failures} failure(s)'}")
    return 0 if failures == 0 else 1


# ============================================================================
# ARGPARSE
# ============================================================================
def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Look up IPs against the IPQualityScore Proxy & VPN Detection API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python ipqs_lookup.py\n"
            "  python ipqs_lookup.py 8.8.8.8 2606:4700:4700::1111\n"
            "  python ipqs_lookup.py --file ips.txt --csv results.csv --only-flagged\n"
            "  python ipqs_lookup.py --file ips.txt --jsonl --redact\n"
            "  python ipqs_lookup.py 8.8.8.8 --user-agent 'Mozilla/5.0 ...' --user-language en-NZ\n"
            "  python ipqs_lookup.py 8.8.8.8 --field billing_phone=64211234567 --field billing_country=NZ\n"
            "  python ipqs_lookup.py 8.8.8.8 --fields fraud_score,proxy,vpn,reasons\n"
            "  python ipqs_lookup.py --config ipqs.json --refresh\n"
            "  python ipqs_lookup.py --postback 1a2b3c4d\n"
            "  python ipqs_lookup.py --self-test\n"
        ),
    )

    parser.add_argument(
        "--config", help="Load configuration overrides from a JSON file."
    )
    parser.add_argument(
        "--api-key",
        help="API key override. Environment variable IPQS_API_KEY is preferred.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline tests and exit.",
    )

    parser.add_argument(
        "ips",
        nargs="*",
        help="IP address(es). Use '-' to read stdin.",
    )
    parser.add_argument(
        "--file",
        "-f",
        help="Read IPs from a file (whitespace/comma/newline separated, # comments).",
    )

    out = parser.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="Output a JSON array.")
    out.add_argument(
        "--jsonl", action="store_true", help="Output one JSON object per line."
    )
    out.add_argument("--csv", metavar="PATH", help="Write results to a CSV file.")
    out.add_argument(
        "--compact",
        "-c",
        action="store_true",
        help="One tab-separated line per IP.",
    )
    out.add_argument(
        "--only-flagged",
        action="store_true",
        help="Hide CLEAN results.",
    )
    out.add_argument(
        "--report",
        action="store_true",
        help="Print a prioritised risk report instead of the summary table.",
    )
    out.add_argument(
        "--redact",
        action="store_true",
        help="Redact obvious PII fields from JSON/JSONL/CSV/human output.",
    )
    out.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    out.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress / footer messages.",
    )
    out.add_argument(
        "--no-header",
        action="store_true",
        help="Do not write a header row when using --csv.",
    )
    out.add_argument(
        "--fields",
        metavar="FIELDS",
        help="Comma-separated field list to display/export (CSV/JSON/JSONL). "
        "Example: fraud_score,proxy,vpn,reasons.",
    )

    q = parser.add_argument_group("IPQS request options")
    q.add_argument(
        "--strictness",
        type=int,
        choices=[0, 1, 2, 3],
        help="0-3. IPQS recommends starting at 0; 2+ = false positives.",
    )
    q.add_argument(
        "--user-agent",
        help="Real visitor user-agent string (improves fraud_score accuracy).",
    )
    q.add_argument("--user-language", help="Real visitor language, e.g. en-NZ.")
    q.add_argument(
        "--mobile",
        action="store_true",
        help="Treat lookup as mobile (only when no UA is available).",
    )
    q.add_argument(
        "--fast",
        action="store_true",
        help="Skip slower forensic checks.",
    )
    q.add_argument(
        "--lighter-penalties",
        action="store_true",
        help="Lower detection/scoring for mixed-quality traffic.",
    )
    q.add_argument(
        "--no-public-access-points",
        action="store_true",
        help="Disable allow_public_access_points.",
    )
    q.add_argument(
        "--transaction-strictness",
        type=int,
        choices=[0, 1, 2],
        help="IPQS transaction_strictness (0-2). Requires transaction fields.",
    )
    q.add_argument(
        "--field",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Send any additional IPQS request field. Repeatable.",
    )
    q.add_argument(
        "--var",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Custom IPQS tracking variable. Repeatable.",
    )

    n = parser.add_argument_group("network / cache")
    n.add_argument(
        "--method",
        choices=["GET", "POST", "get", "post"],
        help="HTTP method (POST is the default).",
    )
    n.add_argument("--workers", type=int, help="Parallel lookups.")
    n.add_argument(
        "--rps",
        type=float,
        help="Maximum request start rate (0 = unlimited).",
    )
    n.add_argument("--timeout", type=float, help="Per-request timeout in seconds.")
    n.add_argument(
        "--retries", type=int, help="Additional retries for transient failures."
    )
    n.add_argument(
        "--max-backoff",
        type=float,
        help="Hard cap on retry sleep in seconds.",
    )
    n.add_argument("--no-cache", action="store_true", help="Disable the local cache.")
    n.add_argument("--cache-ttl", type=float, metavar="HOURS", help="Cache lifetime.")
    n.add_argument("--cache-path", metavar="PATH", help="Override cache file path.")
    n.add_argument(
        "--cache-sensitive",
        action="store_true",
        help="Allow caching responses when sensitive fields are submitted.",
    )
    n.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore cached results but refresh the cache.",
    )
    n.add_argument(
        "--allow-non-public",
        action="store_true",
        help="Look up private/reserved IPs too.",
    )

    # Postback API shortcut
    pb = parser.add_argument_group("postback")
    pb.add_argument(
        "--postback",
        metavar="REQUEST_ID",
        help="Retrieve a past lookup via the Postback API and print the result.",
    )

    return parser.parse_args(argv)


def apply_overrides(args: argparse.Namespace) -> None:
    prm = CONFIG["parameters"]
    net = CONFIG["network"]
    cache_cfg = CONFIG["cache"]

    if args.strictness is not None:
        prm["strictness"] = args.strictness
    if args.user_agent:
        prm["user_agent"] = args.user_agent
    if args.user_language:
        prm["user_language"] = args.user_language
    if args.mobile:
        prm["mobile"] = True
    if args.fast:
        prm["fast"] = True
    if args.lighter_penalties:
        prm["lighter_penalties"] = True
    if args.no_public_access_points:
        prm["allow_public_access_points"] = False
    if args.transaction_strictness is not None:
        prm["transaction_strictness"] = args.transaction_strictness

    if args.field:
        CONFIG["request_fields"].update(
            {
                key: normalize_request_value(value)
                for key, value in parse_key_value(args.field, "--field").items()
            }
        )

    if args.var:
        CONFIG["custom_variables"].update(parse_key_value(args.var, "--var"))

    if args.method:
        CONFIG["method"] = args.method.upper()

    if args.workers is not None:
        net["workers"] = max(1, args.workers)
    if args.rps is not None:
        net["max_rps"] = max(0.0, args.rps)
    if args.timeout is not None:
        net["timeout"] = max(0.1, args.timeout)
    if args.retries is not None:
        net["retries"] = max(0, args.retries)
    if args.max_backoff is not None:
        net["max_backoff"] = max(0.1, args.max_backoff)

    if args.no_cache:
        cache_cfg["enabled"] = False
    if args.cache_ttl is not None:
        cache_cfg["ttl_hours"] = max(0.0, args.cache_ttl)
    if args.cache_path:
        cache_cfg["path"] = args.cache_path
    if args.cache_sensitive:
        cache_cfg["disable_for_sensitive_requests"] = False
    if args.allow_non_public:
        CONFIG["skip_non_public"] = False


# ============================================================================
# MAIN
# ============================================================================
def main(argv: Optional[Sequence[str]] = None) -> int:
    global USE_COLOR

    # Bootstrap pass to locate --config first.
    bootstrap = argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument("--config")
    known, _ = bootstrap.parse_known_args(argv)

    if known.config:
        load_config_file(known.config)

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

    apply_overrides(args)

    api_key = args.api_key or get_api_key()
    if not api_key:
        warn(
            "ERROR: No API key. Set the IPQS_API_KEY environment variable, "
            "use --api-key, or set CONFIG['api_key'].",
            C.RED,
        )
        warn(
            "       Get one (1,000 free lookups) at https://www.ipqualityscore.com/",
            C.GREY,
        )
        return 2

    strictness = int(CONFIG["parameters"].get("strictness", 0))
    if strictness >= 2:
        warn(
            "Warning: strictness 2+ is 'VERY strict' per IPQS and can produce false positives.",
            C.YELLOW,
        )

    if CONFIG["parameters"].get("mobile") and CONFIG["parameters"].get("user_agent"):
        warn(
            "Note: both mobile=true and user_agent supplied. IPQS says mobile "
            "is intended when no UA is available.",
            C.YELLOW,
        )

    # ---- Postback shortcut ----
    if args.postback:
        try:
            data = postback_lookup(args.postback, api_key)
            print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        except Exception as exc:
            warn(f"Postback lookup failed: {exc}", C.RED)
            return 2

    # ---- Collect IPs ----
    raw: List[str] = list(args.ips)

    if args.file:
        try:
            raw.extend(read_ips_from_file(args.file))
        except OSError as exc:
            warn(f"ERROR: cannot read {args.file}: {exc}", C.RED)
            return 2

    if "-" in raw:
        raw = [token for token in raw if token != "-"] + read_ips_from_stdin()

    if not raw and CONFIG.get("target_ips"):
        raw = list(CONFIG["target_ips"])

    if not raw:
        warn("No IPs given.", C.RED)
        return 1

    # ---- Validate / dedupe / filter ----
    exclusions = build_exclusions()
    todo: List[str] = []
    seen = set()

    for token in raw:
        ip = parse_ip(token)
        if ip is None:
            warn(f"Skipping invalid IP: {token}")
            continue

        canonical = ip.compressed
        if canonical in seen:
            continue
        seen.add(canonical)

        if is_excluded(ip, exclusions):
            warn(f"Skipping excluded IP: {canonical}", C.GREY)
            continue

        if CONFIG["skip_non_public"] and not ip.is_global:
            warn(
                f"Skipping non-public IP: {canonical} "
                f"(use --allow-non-public to force)",
                C.GREY,
            )
            continue

        todo.append(canonical)

    if not todo:
        warn("Nothing to look up.")
        return 1

    # ---- Prepare state ----
    params = build_params()

    cache_cfg = CONFIG["cache"]
    cache = Cache(
        enabled=bool(cache_cfg.get("enabled", True)),
        ttl_hours=float(cache_cfg.get("ttl_hours", 6)),
        path=cache_cfg.get("path"),
        refresh=args.refresh,
        allow_sensitive=not bool(cache_cfg.get("disable_for_sensitive_requests", True)),
        schema=int(cache_cfg.get("schema", 4)),
    )

    limiter = RateLimiter(float(CONFIG["network"].get("max_rps", 5.0)))
    abort = threading.Event()

    results: List[Dict[str, Any]] = []
    errors = 0

    verbose = bool(CONFIG.get("log_verbose", True)) and not args.compact
    streaming = not args.json and not args.jsonl

    worker_count = max(1, int(CONFIG["network"].get("workers", 6)))

    # ---- Execute ----
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = [
                pool.submit(process_ip, ip, params, api_key, cache, limiter, abort)
                for ip in todo
            ]

            for future in futures:  # stable output order
                result = future.result()
                results.append(result)

                if result["error"]:
                    errors += 1
                    if not args.quiet:
                        warn(
                            f"[!] {result['ip']}: {result['error']}",
                            C.RED,
                        )
                    continue

                if args.only_flagged and result["analysis"]["verdict"] == "CLEAN":
                    continue

                if streaming and verbose:
                    print_verbose(result, redact=args.redact)
                elif streaming:
                    print_compact(result)

    except KeyboardInterrupt:
        abort.set()
        warn("\nAborted by user.", C.YELLOW)
        return 130
    finally:
        cache.save()

    # ---- Final output ----
    shown = [
        result
        for result in results
        if not args.only_flagged
        or result.get("error")
        or (result.get("analysis") and result["analysis"]["verdict"] != "CLEAN")
    ]

    fields = (
        resolve_fields(
            args.fields.split(",") if args.fields else None,
            CSV_FIELDS,
        )
        if args.fields
        else None
    )

    if args.json:
        payload = [
            result_to_json(result, redact=args.redact, fields=fields)
            for result in shown
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif args.jsonl:
        for result in shown:
            print(
                json.dumps(
                    result_to_json(result, redact=args.redact, fields=fields),
                    ensure_ascii=False,
                )
            )
    elif streaming and verbose and len(shown) > 1:
        if args.report:
            print_risk_report(shown)
        else:
            print_summary_table(shown)

    if args.csv:
        write_csv(
            args.csv,
            shown,
            fields=fields,
            redact=args.redact,
            no_header=args.no_header,
        )
        if not args.quiet:
            warn(f"CSV written to: {args.csv}", C.GREEN)

    # ---- Footer ----
    if not args.quiet:
        ok = [result for result in results if not result["error"]]
        cached_hits = sum(1 for result in ok if result["cached"])
        calls = len(ok) - cached_hits
        counts = {
            verdict: sum(1 for result in ok if result["analysis"]["verdict"] == verdict)
            for verdict in VERDICT_ORDER
        }
        breakdown = "  ".join(
            f"{verdict}: {count}" for verdict, count in counts.items() if count
        )
        warn(
            f"{len(todo)} IP(s) | {calls} API lookup(s), "
            f"{cached_hits} cache hit(s), {errors} failed"
            + (f" | {breakdown}" if breakdown else ""),
            C.GREY,
        )

    return 3 if errors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        warn("\nAborted by user.")
        sys.exit(130)