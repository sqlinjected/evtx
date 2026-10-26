"""Rule-based baseline detections.

These are the week 1 baseline. Week 2 adds embedding-based anomaly scoring on
top, and the README can then compare the two.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parser import Event

BRUTE_FORCE_THRESHOLD = 10   # failures from one source against one account
SPRAY_ACCOUNT_THRESHOLD = 5  # distinct accounts failed from one source
WINDOW = timedelta(minutes=10)

SUSPICIOUS_PATH_HINTS = (
    "\\users\\public\\", "\\appdata\\", "\\temp\\", "\\programdata\\",
    "\\perflogs\\", "\\windows\\temp\\", "cmd.exe /c", "powershell", "-enc", "\\\\",
)


@dataclass
class Finding:
    rule: str
    severity: str  # low / medium / high
    summary: str
    events: list[Event] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "summary": self.summary,
            "event_count": len(self.events),
            "first_seen": self.events[0].timestamp if self.events else None,
            "last_seen": self.events[-1].timestamp if self.events else None,
            "record_ids": [e.record_id for e in self.events],
        }


def _ts(e: Event) -> datetime:
    t = e.timestamp.replace("Z", "+00:00")
    # trim sub-microsecond digits some logs carry
    if "." in t:
        head, rest = t.split(".", 1)
        frac = "".join(ch for ch in rest if ch.isdigit())[:6]
        tz = rest[len("".join(ch for ch in rest if ch.isdigit())):]
        t = f"{head}.{frac}{tz}"
    return datetime.fromisoformat(t)


def _source(e: Event) -> str:
    ip = e.get("IpAddress")
    if ip and ip not in ("-", "::1", "127.0.0.1"):
        return str(ip)
    return str(e.get("WorkstationName") or ip or "unknown")


def _windows(events: list[Event]) -> list[list[Event]]:
    """Group time-sorted events into bursts where each gap is under WINDOW."""
    groups: list[list[Event]] = []
    for e in events:
        if groups and _ts(e) - _ts(groups[-1][-1]) <= WINDOW:
            groups[-1].append(e)
        else:
            groups.append([e])
    return groups


def detect_failed_logons(events: list[Event]) -> list[Finding]:
    by_source: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_id == 4625:
            by_source[_source(e)].append(e)

    findings: list[Finding] = []
    for src, evs in by_source.items():
        for burst in _windows(evs):
            accounts = {str(e.get("TargetUserName", "")).lower() for e in burst}
            if len(accounts) >= SPRAY_ACCOUNT_THRESHOLD:
                findings.append(Finding(
                    "password_spray", "high",
                    f"{len(burst)} failed logons from {src} across {len(accounts)} different accounts",
                    burst,
                ))
                continue
            per_account: dict[str, list[Event]] = defaultdict(list)
            for e in burst:
                per_account[str(e.get("TargetUserName", ""))].append(e)
            for acct, hits in per_account.items():
                if len(hits) >= BRUTE_FORCE_THRESHOLD:
                    findings.append(Finding(
                        "brute_force", "medium",
                        f"{len(hits)} failed logons for '{acct}' from {src}",
                        hits,
                    ))
    return findings


def detect_service_installs(events: list[Event]) -> list[Finding]:
    findings = []
    for e in events:
        if e.event_id != 7045:
            continue
        name = e.get("ServiceName", "?")
        path = str(e.get("ImagePath", ""))
        hits = [h for h in SUSPICIOUS_PATH_HINTS if h in path.lower()]
        severity = "high" if hits else "low"
        why = f" (suspicious: {', '.join(hits)})" if hits else ""
        findings.append(Finding(
            "service_install", severity,
            f"Service '{name}' installed with path {path}{why}",
            [e],
        ))
    return findings


def detect_log_clears(events: list[Event]) -> list[Finding]:
    return [
        Finding(
            "security_log_cleared", "high",
            f"Security log cleared by {e.get('SubjectDomainName', '?')}\\{e.get('SubjectUserName', '?')}",
            [e],
        )
        for e in events if e.event_id == 1102
    ]


def run_all(events: list[Event]) -> list[Finding]:
    order = {"high": 0, "medium": 1, "low": 2}
    findings = detect_log_clears(events) + detect_failed_logons(events) + detect_service_installs(events)
    return sorted(findings, key=lambda f: order[f.severity])
