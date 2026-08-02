#!/usr/bin/env python3
"""
LogSentry - Analyseur de logs d'authentification SSH

Détecte des patterns d'attaque courants (brute-force, énumération de
comptes, compromission probable) dans un fichier auth.log au format
syslog standard, et mappe chaque détection à une technique MITRE ATT&CK.

Usage :
    python3 log_analyzer.py sample_logs/auth.log.sample
    python3 log_analyzer.py /var/log/auth.log -o rapport.json

Auteur: Mustapha Zouaoui
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# --- Patterns de parsing (format syslog standard Debian/Ubuntu) ---

LINE_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$'
)

FAILED_INVALID_RE = re.compile(
    r'Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port \d+'
)
FAILED_VALID_RE = re.compile(
    r'Failed password for (?!invalid user)(?P<user>\S+) from (?P<ip>\S+) port \d+'
)
ACCEPTED_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+'
)

# --- Référentiel MITRE ATT&CK (sous-ensemble pertinent) ---

MITRE = {
    "brute_force": {"id": "T1110.001", "name": "Brute Force: Password Guessing"},
    "enumeration": {"id": "T1087.001", "name": "Account Discovery: Local Account"},
    "compromise": {"id": "T1078", "name": "Valid Accounts"},
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def parse_line(line, year):
    """Parse une ligne auth.log -> dict d'événement, ou None si non pertinente."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None

    try:
        ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    msg = m.group('msg')

    fm = FAILED_INVALID_RE.search(msg)
    if fm:
        return {"ts": ts, "ip": fm.group('ip'), "user": fm.group('user'),
                 "event": "failed", "valid_user": False}

    fm = FAILED_VALID_RE.search(msg)
    if fm:
        return {"ts": ts, "ip": fm.group('ip'), "user": fm.group('user'),
                 "event": "failed", "valid_user": True}

    am = ACCEPTED_RE.search(msg)
    if am:
        return {"ts": ts, "ip": am.group('ip'), "user": am.group('user'),
                 "event": "success", "valid_user": True}

    return None


def load_events(path, year):
    events = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            evt = parse_line(line, year)
            if evt:
                events.append(evt)
    return events


def max_events_in_window(sorted_events, window):
    """Nombre maximum d'événements contenus dans une fenêtre glissante."""
    best = 0
    for i, e in enumerate(sorted_events):
        count = 1
        for e2 in sorted_events[i + 1:]:
            if e2['ts'] - e['ts'] <= window:
                count += 1
            else:
                break
        best = max(best, count)
    return best


def analyze(events, brute_threshold, enum_threshold, window_minutes):
    window = timedelta(minutes=window_minutes)
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e['ip']].append(e)

    findings = []

    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e['ts'])
        failed = [e for e in evs if e['event'] == 'failed']
        successes = [e for e in evs if e['event'] == 'success']
        distinct_users_failed = {e['user'] for e in failed}

        # Règle 1 : brute-force (rafale de tentatives échouées)
        if failed:
            max_burst = max_events_in_window(failed, window)
            if max_burst >= brute_threshold:
                findings.append({
                    "type": "brute_force",
                    "ip": ip,
                    "severity": "high",
                    "count": max_burst,
                    "window_minutes": window_minutes,
                    "first_seen": failed[0]['ts'].isoformat(),
                    "last_seen": failed[-1]['ts'].isoformat(),
                    "mitre": MITRE["brute_force"],
                    "description": (
                        f"{max_burst} tentatives de connexion échouées depuis {ip} "
                        f"en moins de {window_minutes} min."
                    ),
                })

        # Règle 2 : énumération de comptes (beaucoup de users distincts testés)
        if len(distinct_users_failed) >= enum_threshold:
            findings.append({
                "type": "enumeration",
                "ip": ip,
                "severity": "medium",
                "count": len(distinct_users_failed),
                "users": sorted(distinct_users_failed)[:20],
                "first_seen": failed[0]['ts'].isoformat(),
                "last_seen": failed[-1]['ts'].isoformat(),
                "mitre": MITRE["enumeration"],
                "description": (
                    f"{len(distinct_users_failed)} noms d'utilisateur distincts "
                    f"testés depuis {ip}."
                ),
            })

        # Règle 3 : compromission probable (succès après une rafale d'échecs)
        if successes and len(failed) >= max(3, brute_threshold // 2):
            first_fail_ts = failed[0]['ts']
            for s in successes:
                if s['ts'] >= first_fail_ts:
                    findings.append({
                        "type": "compromise",
                        "ip": ip,
                        "severity": "critical",
                        "user": s['user'],
                        "failed_before_success": len(failed),
                        "success_time": s['ts'].isoformat(),
                        "mitre": MITRE["compromise"],
                        "description": (
                            f"Connexion réussie ('{s['user']}') depuis {ip} après "
                            f"{len(failed)} échec(s) — compte potentiellement compromis."
                        ),
                    })

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 9))
    return findings


def print_report(findings, total_events, ip_count):
    print(f"\nLogSentry — {total_events} événement(s) analysé(s), {ip_count} adresse(s) IP source(s)\n")

    if not findings:
        print("Aucun pattern suspect détecté par les règles actuelles.\n")
        return

    for f in findings:
        tag = f"[{f['severity'].upper()}]"
        print(f"{tag:<12} {f['mitre']['id']} — {f['mitre']['name']}")
        print(f"             IP source : {f['ip']}")
        print(f"             {f['description']}")
        if f['type'] == 'enumeration':
            preview = ", ".join(f['users'][:8])
            more = "..." if f['count'] > 8 else ""
            print(f"             Comptes testés : {preview}{more}")
        print()

    severities = [f['severity'] for f in findings]
    summary = ", ".join(f"{severities.count(s)} {s}" for s in ("critical", "high", "medium", "low") if s in severities)
    print(f"Résumé : {len(findings)} constat(s) — {summary}\n")


def main():
    parser = argparse.ArgumentParser(
        description="LogSentry - analyseur de logs SSH avec détection de patterns et mapping MITRE ATT&CK."
    )
    parser.add_argument("logfile", help="Chemin vers le fichier auth.log à analyser")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                         help="Année à utiliser pour interpréter les timestamps (défaut : année courante)")
    parser.add_argument("--brute-threshold", type=int, default=5,
                         help="Nombre de tentatives échouées déclenchant une alerte brute-force (défaut : 5)")
    parser.add_argument("--enum-threshold", type=int, default=5,
                         help="Nombre de comptes distincts testés déclenchant une alerte d'énumération (défaut : 5)")
    parser.add_argument("--window", type=int, default=5,
                         help="Fenêtre glissante en minutes pour la détection de brute-force (défaut : 5)")
    parser.add_argument("-o", "--output", help="Exporter le rapport complet en JSON")
    args = parser.parse_args()

    try:
        events = load_events(args.logfile, args.year)
    except FileNotFoundError:
        print(f"[!] Fichier introuvable : {args.logfile}")
        sys.exit(1)

    if not events:
        print("[!] Aucune ligne SSH reconnue dans ce fichier. Vérifie le format (syslog standard attendu).")
        sys.exit(1)

    findings = analyze(events, args.brute_threshold, args.enum_threshold, args.window)
    ip_count = len({e['ip'] for e in events})
    print_report(findings, len(events), ip_count)

    if args.output:
        report = {
            "logfile": args.logfile,
            "generated_at": datetime.now().isoformat(),
            "total_events": len(events),
            "distinct_ips": ip_count,
            "findings": findings,
        }
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"Rapport exporté vers {args.output}\n")


if __name__ == "__main__":
    main()
