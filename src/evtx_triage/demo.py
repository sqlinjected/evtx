"""Built-in synthetic events, so the tool can be tried without a VM or real logs.

Run: evtx-triage --demo

Every value here is made up. Addresses come from the documentation ranges
(203.0.113.0/24 and 10.0.0.0/8), and the host is a fake lab machine.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .parser import Event

_T0 = datetime(2026, 10, 20, 2, 14, 0, tzinfo=timezone.utc)
_HOST = "LAB-WS01"


def _ev(eid: int, seconds: int, channel: str, rid: int, **fields) -> Event:
    ts = (_T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return Event(eid, ts, _HOST, channel, rid, dict(fields), "demo")


def demo_events() -> list[Event]:
    events: list[Event] = []
    rid = 1000

    # Brute force: one source hammering the administrator account
    for i in range(14):
        rid += 1
        events.append(_ev(4625, i * 6, "Security", rid,
                          TargetUserName="administrator", IpAddress="203.0.113.44", LogonType="3"))

    # Password spray: one source, one try each against many accounts
    for i, user in enumerate(["alice", "bob", "carol", "dave", "erin", "frank", "grace"]):
        rid += 1
        events.append(_ev(4625, 600 + i * 20, "Security", rid,
                          TargetUserName=user, IpAddress="10.0.0.77", LogonType="3"))

    # A normal typo, which should stay quiet
    for i in range(2):
        rid += 1
        events.append(_ev(4625, 900 + i * 30, "Security", rid,
                          TargetUserName="pat", IpAddress="10.0.0.12", LogonType="2"))

    # Service installs: a mix the rules get right, and some they don't
    services = [
        ("TriageBenign", r"C:\Windows\System32\svchost.exe -k netsvcs", "LocalSystem"),
        ("NVDisplay.ContainerLocalSystem",
         r'"C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe" -s NVDisplay.ContainerLocalSystem',
         "LocalSystem"),
        ("WinUpdateHelper", r"C:\Users\Public\updater.exe", "LocalSystem"),
        ("MsDataSync", r"C:\Windows\mdsvc32.exe -silent", "LocalSystem"),
        ("cqzlrwm", r"%COMSPEC% /b /c start /b /min rundll32.exe %SystemRoot%\cqzlrwm.dll,Run", "LocalSystem"),
    ]
    for i, (name, path, acct) in enumerate(services):
        rid += 1
        events.append(_ev(7045, 1500 + i * 45, "System", rid,
                          ServiceName=name, ImagePath=path, AccountName=acct,
                          ServiceType="user mode service", StartType="auto start"))

    # The attacker clears the Security log on the way out
    rid += 1
    events.append(_ev(1102, 2000, "Security", rid,
                      SubjectUserName="administrator", SubjectDomainName=_HOST))

    events.sort(key=lambda e: e.timestamp)
    return events
