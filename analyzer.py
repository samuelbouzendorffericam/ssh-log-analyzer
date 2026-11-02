#!/usr/bin/env python3
"""analyzer : détecte les tentatives de brute force SSH dans un fichier auth.log.

Outil défensif (blue team) : il lit un journal existant, il n'envoie rien
sur le réseau et ne touche à aucun système.
Format attendu : journaux OpenSSH de type syslog (ex. /var/log/auth.log).
"""
import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

LINE_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+")


@dataclass(frozen=True)
class Event:
    when: datetime
    kind: str  # "failed" ou "accepted"
    user: str
    ip: str


def parse_line(line: str, year: int):
    """Retourne un Event, ou None si la ligne n'est pas une connexion SSH."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    for kind, regex in (("failed", FAILED_RE), ("accepted", ACCEPTED_RE)):
        found = regex.search(m.group("msg"))
        if found:
            when = datetime.strptime(
                f"{year} {m.group('month')} {m.group('day')} {m.group('time')}", "%Y %b %d %H:%M:%S"
            )
            return Event(when, kind, found.group("user"), found.group("ip"))
    return None


def parse_lines(lines, year: int) -> list:
    events = (parse_line(line, year) for line in lines)
    return sorted((e for e in events if e), key=lambda e: e.when)


def max_failures_in_window(times: list, window: timedelta) -> int:
    """Plus grand nombre d'échecs dans une fenêtre glissante (liste triée)."""
    best, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def brute_force_ips(events: list, threshold: int = 5, window_seconds: int = 60) -> dict:
    """{ip: échecs max dans la fenêtre} pour les IP au-dessus du seuil."""
    window = timedelta(seconds=window_seconds)
    failed_times = {}
    for e in events:
        if e.kind == "failed":
            failed_times.setdefault(e.ip, []).append(e.when)
    result = {ip: max_failures_in_window(ts, window) for ip, ts in failed_times.items()}
    return {ip: n for ip, n in sorted(result.items(), key=lambda kv: -kv[1]) if n >= threshold}


def success_after_failures(events: list, threshold: int = 5, window_seconds: int = 60) -> list:
    """Connexions réussies précédées d'au moins `threshold` échecs de la même IP."""
    window = timedelta(seconds=window_seconds)
    alerts = []
    for e in events:
        if e.kind != "accepted":
            continue
        recent = [f for f in events
                  if f.kind == "failed" and f.ip == e.ip and timedelta(0) <= e.when - f.when <= window]
        if len(recent) >= threshold:
            alerts.append({"ip": e.ip, "user": e.user, "when": e.when.isoformat(sep=" "),
                           "failures_before": len(recent)})
    return alerts


def analyze(events: list, threshold: int = 5, window_seconds: int = 60) -> dict:
    failed = [e for e in events if e.kind == "failed"]
    return {
        "events": len(events),
        "failed_attempts": len(failed),
        "top_ips": Counter(e.ip for e in failed).most_common(5),
        "targeted_users": Counter(e.user for e in failed).most_common(5),
        "brute_force_ips": brute_force_ips(events, threshold, window_seconds),
        "success_after_failures": success_after_failures(events, threshold, window_seconds),
    }


def format_report(report: dict, threshold: int, window_seconds: int) -> str:
    out = [
        f"Événements SSH analysés : {report['events']}",
        f"Échecs de connexion     : {report['failed_attempts']}",
        "",
        "IP les plus actives (échecs) :",
        *[f"  {ip:<16} {n}" for ip, n in report["top_ips"]],
        "",
        "Comptes les plus ciblés :",
        *[f"  {user:<16} {n}" for user, n in report["targeted_users"]],
        "",
        f"ALERTE brute force (≥ {threshold} échecs en {window_seconds} s) :",
    ]
    out += [f"  {ip:<16} {n} échecs dans la fenêtre" for ip, n in report["brute_force_ips"].items()] \
        or ["  aucune"]
    out += ["", "ALERTE CRITIQUE (connexion réussie après une rafale d'échecs) :"]
    out += [f"  {a['when']}  {a['ip']} a réussi à se connecter en tant que '{a['user']}' "
            f"après {a['failures_before']} échecs" for a in report["success_after_failures"]] or ["  aucune"]
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Détection de brute force SSH dans auth.log.")
    parser.add_argument("logfile")
    parser.add_argument("--threshold", type=int, default=5, help="échecs pour déclencher l'alerte")
    parser.add_argument("--window", type=int, default=60, help="fenêtre en secondes")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="année des journaux (absente du format syslog)")
    parser.add_argument("--json", action="store_true", help="sortie JSON")
    args = parser.parse_args()

    with open(args.logfile, encoding="utf-8", errors="replace") as f:
        events = parse_lines(f, args.year)
    report = analyze(events, args.threshold, args.window)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_report(report, args.threshold, args.window))


if __name__ == "__main__":
    main()
