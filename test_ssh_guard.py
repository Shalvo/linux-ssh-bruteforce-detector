"""Tests for ssh_guard. Run with: pytest -v"""
import json
from datetime import datetime, timedelta

import ssh_guard as sg


def line(ts, msg, host="web01", pid=1000):
    return f"{ts} {host} sshd[{pid}]: {msg}"


def fails(ip, count, start="Oct 19 10:00:00", step_seconds=30, user="root"):
    base = datetime.strptime("2026 " + start, "%Y %b %d %H:%M:%S")
    out = []
    for i in range(count):
        t = (base + timedelta(seconds=i * step_seconds)).strftime("%b %d %H:%M:%S")
        out.append(line(t, f"Failed password for {user} from {ip} port {40000 + i} ssh2"))
    return out


def test_parses_classic_syslog_failure():
    events = sg.parse_lines([line("Oct  3 07:12:10", "Failed password for invalid user admin from 203.0.113.45 port 40001 ssh2")], 2026)
    assert len(events) == 1
    e = events[0]
    assert e.kind == "fail" and e.user == "admin" and e.ip == "203.0.113.45" and e.invalid_user
    assert e.when == datetime(2026, 10, 3, 7, 12, 10)


def test_parses_rfc3339_timestamp_and_success():
    raw = "2026-10-19T13:21:10.123456+03:00 web01 sshd[4407]: Accepted password for deploy from 192.0.2.10 port 60107 ssh2"
    events = sg.parse_lines([raw], 2026)
    assert events[0].kind == "success"
    assert events[0].when == datetime(2026, 10, 19, 13, 21, 10, 123456)


def test_parses_ipv6_source():
    events = sg.parse_lines([line("Oct 19 10:00:00", "Failed password for root from 2001:db8::7 port 5000 ssh2")], 2026)
    assert events[0].ip == "2001:db8::7"


def test_ignores_unrelated_lines():
    noise = [
        "Oct 19 15:10:00 web01 CRON[4600]: pam_unix(cron:session): session opened for user root",
        line("Oct 19 07:16:02", "Disconnecting authenticating user root 203.0.113.45 port 40011 [preauth]"),
        line("Oct 19 07:16:02", "Invalid user admin from 203.0.113.45 port 40001"),
    ]
    assert sg.parse_lines(noise, 2026) == []


def test_brute_force_flagged_at_threshold():
    reports = sg.analyse(sg.parse_lines(fails("203.0.113.45", 5), 2026), threshold=5, window_minutes=10)
    r = reports["203.0.113.45"]
    assert r.brute_force and r.risk == "HIGH" and r.peak_in_window == 5


def test_slow_attempts_outside_window_not_brute_force():
    # 5 failures, one every 20 minutes: never 5 inside a 10-minute window
    events = sg.parse_lines(fails("198.51.100.23", 5, step_seconds=20 * 60), 2026)
    r = sg.analyse(events, threshold=5, window_minutes=10)["198.51.100.23"]
    assert not r.brute_force and r.risk == "LOW" and r.peak_in_window == 1


def test_success_after_repeated_failures_is_critical():
    lines = fails("192.0.2.10", 4, user="deploy") + [
        line("Oct 19 10:05:00", "Accepted password for deploy from 192.0.2.10 port 60107 ssh2")
    ]
    r = sg.analyse(sg.parse_lines(lines, 2026))["192.0.2.10"]
    assert r.risk == "CRITICAL" and r.compromised_users == {"deploy"}


def test_single_typo_then_success_is_not_flagged():
    lines = fails("10.0.0.5", 1, user="shalvin") + [
        line("Oct 19 10:00:10", "Accepted password for shalvin from 10.0.0.5 port 50602 ssh2")
    ]
    r = sg.analyse(sg.parse_lines(lines, 2026))["10.0.0.5"]
    assert r.risk == "LOW" and not r.success_after_failures


def test_peak_in_window_boundary():
    t0 = datetime(2026, 10, 19, 10, 0, 0)
    times = [t0, t0 + timedelta(minutes=10), t0 + timedelta(minutes=10, seconds=1)]
    assert sg.peak_in_window(times, timedelta(minutes=10)) == 2


def test_ranking_puts_critical_first_and_hides_clean_ips():
    lines = (
        fails("203.0.113.45", 6)
        + fails("192.0.2.10", 3, user="deploy")
        + [line("Oct 19 10:02:00", "Accepted password for deploy from 192.0.2.10 port 1 ssh2"),
           line("Oct 19 10:03:00", "Accepted publickey for shalvin from 10.0.0.9 port 2 ssh2")]
    )
    rows = sg.ranked(sg.analyse(sg.parse_lines(lines, 2026)))
    assert [r.ip for r in rows] == ["192.0.2.10", "203.0.113.45"]


def test_block_suggestions_only_for_high_and_critical():
    lines = fails("203.0.113.45", 6) + fails("198.51.100.23", 2)
    rows = sg.ranked(sg.analyse(sg.parse_lines(lines, 2026)))
    assert sg.block_suggestions(rows) == ["sudo ufw deny from 203.0.113.45 to any port 22"]


def test_cli_json_on_sample_log(capsys):
    assert sg.main(["sample_auth.log", "--json", "--year", "2026"]) == 0
    data = json.loads(capsys.readouterr().out)
    risks = {d["ip"]: d["risk"] for d in data}
    assert risks["192.0.2.10"] == "CRITICAL"
    assert risks["203.0.113.45"] == "HIGH"
    assert risks["198.51.100.23"] == "LOW"


def test_cli_fail_on_threat_exit_code():
    assert sg.main(["sample_auth.log", "--fail-on-threat", "--year", "2026"]) == 1
