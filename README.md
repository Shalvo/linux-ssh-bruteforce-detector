# linux-ssh-bruteforce-detector

![CI](https://github.com/Shalvo/linux-ssh-bruteforce-detector/actions/workflows/ci.yml/badge.svg)

A small Python command-line tool that reads a Linux SSH authentication log and
tells you which source IPs are attacking the server, and, more importantly,
whether any of them actually got in.

It flags two things:

| Finding | What it means | Risk |
|---|---|---|
| **Success after failures** | An IP failed several times and then logged in. Often a guessed or sprayed password. | CRITICAL |
| **Brute force** | An IP hit the failure threshold inside a sliding time window. | HIGH |
| Low-volume failures | Failures below the threshold (typos, slow scanners). | LOW |

Standard library only, no dependencies to run it. Nothing is blocked
automatically: the tool can print suggested `ufw` rules for a human to review.

## Example

```text
$ python ssh_guard.py sample_auth.log --suggest-blocks --year 2026
SSH guard report: 25 login events, 4 source IP(s) listed

RISK      IP              FAILS  PEAK/10m  NOTE
CRITICAL  192.0.2.10          6         6  login succeeded as deploy after 6 failures
HIGH      203.0.113.45       12        12  brute force, 8 usernames tried
LOW       198.51.100.23       3         1  below threshold
LOW       10.0.0.5            1         1  below threshold

Suggested firewall rules (review before running):
  sudo ufw deny from 192.0.2.10 to any port 22
  sudo ufw deny from 203.0.113.45 to any port 22
```

The sample log uses the RFC 5737 documentation IP ranges, so none of the
addresses are real.

## Usage

```bash
# Debian / Ubuntu
sudo python3 ssh_guard.py /var/log/auth.log

# RHEL / Rocky / Alma
sudo python3 ssh_guard.py /var/log/secure

# systemd journal (pipe into stdin)
journalctl -u ssh --since today --no-pager -o short-iso | python3 ssh_guard.py -
```

| Option | Default | Purpose |
|---|---|---|
| `--threshold N` | 5 | Failures inside the window that count as brute force |
| `--window MIN` | 10 | Sliding window in minutes |
| `--min-failures-before-success N` | 3 | Failures before a successful login that make it suspicious |
| `--year YYYY` | current year | Classic syslog timestamps omit the year |
| `--json` | off | Machine-readable output (for SIEM ingestion or scripts) |
| `--all` | off | Also list IPs with no failures |
| `--suggest-blocks` | off | Print `ufw deny` commands for HIGH/CRITICAL IPs |
| `--fail-on-threat` | off | Exit code 1 if anything HIGH/CRITICAL is found (useful in cron or monitoring) |

## How it works

1. Regular expressions pull failed and accepted logins out of the log. Both
   classic syslog (`Oct 19 07:12:10`) and RFC 3339 timestamps are supported,
   as are IPv4 and IPv6 sources.
2. Events are grouped by source IP and sorted by time.
3. A sliding window finds the peak number of failures in any `--window`
   minutes, which separates a burst attack from slow background noise.
4. For each successful login the tool checks how many failures came first from
   the same IP. A single typo followed by a login is ignored; a run of failures
   followed by a login is CRITICAL.

## Tests

```bash
pip install -r requirements.txt
pytest -v
```

Tests run on every push via GitHub Actions against Python 3.10, 3.11 and 3.12.

## Roadmap

- [ ] Allow-list of trusted IPs and networks
- [ ] GeoIP / ASN enrichment for attacking IPs
- [ ] Run on a schedule with a systemd timer and send alerts
- [ ] Forward JSON findings to Azure Log Analytics / Microsoft Sentinel
- [ ] Equivalent detection written in KQL for Sentinel

## Why I built this

SSH exposed to the internet attracts constant password guessing. Tools like
fail2ban block noisy IPs, but the question that matters during an incident is
"did any of them get in?". This project was built as part of my security
engineering practice to answer that question quickly from the raw logs.

## Licence

MIT
