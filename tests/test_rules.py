import json

from evtx_triage.parser import normalize
from evtx_triage.rules import run_all


def rec(eid, minute, event_data=None, user_data=None, rid=1):
    event = {
        "System": {
            "EventID": {"#text": eid} if eid == 7045 else eid,
            "TimeCreated": {"#attributes": {"SystemTime": f"2026-10-07T12:{minute:02d}:00.0000000Z"}},
            "Computer": "VM-01",
            "Channel": "Security",
        }
    }
    if event_data is not None:
        event["EventData"] = event_data
    if user_data is not None:
        event["UserData"] = user_data
    return {"event_record_id": rid, "data": json.dumps({"Event": event})}


def test_ignores_unwatched_ids():
    assert normalize(rec(4624, 0, {})) is None


def test_1102_reads_userdata():
    ev = normalize(rec(1102, 0, user_data={"LogFileCleared": {"SubjectUserName": "admin", "SubjectDomainName": "VM"}}))
    assert ev.event_id == 1102 and ev.get("SubjectUserName") == "admin"
    assert run_all([ev])[0].rule == "security_log_cleared"


def test_brute_force_and_spray():
    brute = [normalize(rec(4625, i % 5, {"TargetUserName": "administrator", "IpAddress": "10.0.0.5"}, rid=i)) for i in range(12)]
    spray = [normalize(rec(4625, 30, {"TargetUserName": u, "IpAddress": "10.0.0.9"})) for u in "abcdef"]
    rules = {f.rule for f in run_all(brute + spray)}
    assert rules == {"brute_force", "password_spray"}


def test_few_failures_is_quiet():
    evs = [normalize(rec(4625, 0, {"TargetUserName": "bob", "IpAddress": "10.0.0.5"})) for _ in range(3)]
    assert run_all(evs) == []


def test_service_path_severity():
    good = normalize(rec(7045, 0, {"ServiceName": "Ok", "ImagePath": "C:\\Windows\\System32\\svchost.exe -k netsvcs"}))
    bad = normalize(rec(7045, 1, {"ServiceName": "WinUpdateHelper", "ImagePath": "C:\\Users\\Public\\updater.exe"}))
    sev = {f.summary.split("'")[1]: f.severity for f in run_all([good, bad])}
    assert sev == {"Ok": "low", "WinUpdateHelper": "high"}
