#!/usr/bin/env python3
"""
ssh_guard: detect SSH brute-force activity in Linux authentication logs.

Reads an OpenSSH auth log (/var/log/auth.log on Debian/Ubuntu, /var/log/secure
on RHEL/Rocky), groups login attempts by source IP and flags:

  * brute force: an IP with at least THRESHOLD failed logins inside a WINDOW
  * success after failures: an IP that logged in successfully after repeated
    failures, which can mean a guessed password and needs investigating

Standard library only. Nothing is blocked automatically; suggested firewall
commands are printed for a human to review first.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

# Classic syslog ("Oct 19 03:14:07") or RFC 3339 ("2026-10-19T03:14:07.123456+03:00")
TS = (
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"
    r"|[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})"
)
PREFIX = TS + r"\s+\S+\s+sshd(?:\[\d+\])?:\s+"
IP = r"(?P<ip>[0-9a-fA-F:.]+)"

FAILED_RE = re.compile(
    PREFIX + r"Failed (?:password|publickey) for (?P<invalid>invalid user )?(?P<user>\S+) from " + IP
)
ACCEPTED_RE = re.compile(PREFIX + r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP)


@dataclass
class Event:
    when: datetime
    kind: str  # "fail" or "success"
    user: str
    ip: str
    invalid_user: bool = False


@dataclass
class IpReport:
    ip: str
    failures: int = 0
    successes: int = 0
    users_tried: set = field(default_factory=set)
    invalid_users: set = field(default_factory=set)
    compromised_users: set = field(default_factory=set)
    peak_in_window: int = 0
    brute_force: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    def success_after_failures(self) -> bool:
        return bool(self.compromised_users)

    @property
    def risk(self) -> str:
        if self.success_after_failures:
            return "CRITICAL"
        if self.brute_force:
            return "HIGH"
        if self.failures:
            return "LOW"
        return "NONE"

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "risk": self.risk,
            "failures": self.failures,
            "successes": self.successes,
            "peak_in_window": self.peak_in_window,
            "brute_force": self.brute_force,
            "success_after_failures": self.success_after_failures,
            "compromised_users": sorted(self.compromised_users),
            "users_tried": sorted(self.users_tried),
            "invalid_users": sorted(self.invalid_users),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


def parse_timestamp(ts: str, year: int) -> datetime:
    """Turn a syslog or RFC 3339 timestamp into a naive datetime."""
    if ts[0].isdigit():
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse_lines(lines: Iterable[str], year: int) -> list[Event]:
    """Extract failed and successful SSH logins. Unrelated lines are ignored."""
    events = []
    for line in lines:
        m = FAILED_RE.search(line)
        if m:
            events.append(Event(parse_timestamp(m["ts"], year), "fail", m["user"], m["ip"], bool(m["invalid"])))
            continue
        m = ACCEPTED_RE.search(line)
        if m:
            events.append(Event(parse_timestamp(m["ts"], year), "success", m["user"], m["ip"]))
    return events


def peak_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of events that fall inside any sliding window."""
    times = sorted(times)
    best = start = 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyse(events: list[Event], threshold: int = 5, window_minutes: int = 10,
            min_failures_before_success: int = 3) -> dict[str, IpReport]:
    window = timedelta(minutes=window_minutes)
    reports: dict[str, IpReport] = {}
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda e: e.when)
        r = IpReport(ip=ip, first_seen=ip_events[0].when, last_seen=ip_events[-1].when)
        fail_times = []
        for e in ip_events:
            if e.kind == "fail":
                r.failures += 1
                r.users_tried.add(e.user)
                if e.invalid_user:
                    r.invalid_users.add(e.user)
                fail_times.append(e.when)
            else:
                r.successes += 1
                if len(fail_times) >= min_failures_before_success:
                    r.compromised_users.add(e.user)
        r.peak_in_window = peak_in_window(fail_times, window) if fail_times else 0
        r.brute_force = r.peak_in_window >= threshold
        reports[ip] = r
    return reports


RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "LOW": 2, "NONE": 3}


def ranked(reports: dict[str, IpReport], include_clean: bool = False) -> list[IpReport]:
    rows = [r for r in reports.values() if include_clean or r.failures]
    return sorted(rows, key=lambda r: (RISK_ORDER[r.risk], -r.failures, r.ip))


def format_table(rows: list[IpReport], window_minutes: int, total_events: int) -> str:
    out = [f"SSH guard report: {total_events} login events, {len(rows)} source IP(s) listed", ""]
    if not rows:
        out.append("No failed logins found.")
        return "\n".join(out)
    w = max(15, max(len(r.ip) for r in rows))
    out.append(f"{'RISK':<9} {'IP':<{w}} {'FAILS':>5} {'PEAK/' + str(window_minutes) + 'm':>9}  NOTE")
    for r in rows:
        if r.success_after_failures:
            note = f"login succeeded as {', '.join(sorted(r.compromised_users))} after {r.failures} failures"
        elif r.brute_force:
            note = f"brute force, {len(r.users_tried)} usernames tried"
        else:
            note = "below threshold"
        out.append(f"{r.risk:<9} {r.ip:<{w}} {r.failures:>5} {r.peak_in_window:>9}  {note}")
    return "\n".join(out)


def block_suggestions(rows: list[IpReport]) -> list[str]:
    return [f"sudo ufw deny from {r.ip} to any port 22" for r in rows if r.risk in ("CRITICAL", "HIGH")]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Detect SSH brute-force activity in Linux auth logs.")
    p.add_argument("logfile", help="path to auth.log / secure, or '-' to read stdin")
    p.add_argument("--threshold", type=int, default=5, help="failures inside the window that count as brute force (default 5)")
    p.add_argument("--window", type=int, default=10, help="sliding window in minutes (default 10)")
    p.add_argument("--min-failures-before-success", type=int, default=3,
                   help="failures before a successful login that make it suspicious (default 3)")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for classic syslog timestamps, which omit it (default: current year)")
    p.add_argument("--json", action="store_true", help="print results as JSON")
    p.add_argument("--all", action="store_true", help="include IPs with no failed logins")
    p.add_argument("--suggest-blocks", action="store_true", help="print ufw commands for HIGH/CRITICAL IPs (not executed)")
    p.add_argument("--fail-on-threat", action="store_true", help="exit with code 1 if any HIGH/CRITICAL IP is found")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.logfile == "-":
        lines = sys.stdin.readlines()
    else:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

    events = parse_lines(lines, args.year)
    reports = analyse(events, args.threshold, args.window, args.min_failures_before_success)
    rows = ranked(reports, include_clean=args.all)

    if args.json:
        print(json.dumps([r.to_dict() for r in rows], indent=2))
    else:
        print(format_table(rows, args.window, len(events)))
        if args.suggest_blocks:
            cmds = block_suggestions(rows)
            if cmds:
                print("\nSuggested firewall rules (review before running):")
                print("\n".join("  " + c for c in cmds))

    threat = any(r.risk in ("CRITICAL", "HIGH") for r in rows)
    return 1 if (args.fail_on_threat and threat) else 0


if __name__ == "__main__":
    sys.exit(main())
