"""Read .evtx files and turn the records we care about into flat Event objects."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

WATCHED_IDS = {4625, 7045, 1102}


@dataclass
class Event:
    event_id: int
    timestamp: str
    computer: str
    channel: str
    record_id: int | None
    fields: dict[str, Any] = field(default_factory=dict)
    source_file: str = ""

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)


def _event_id(system: dict) -> int | None:
    raw = system.get("EventID")
    # EventID is either a bare int or {"#text": 4625, "#attributes": {...}}
    if isinstance(raw, dict):
        raw = raw.get("#text")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _flatten_data(event: dict) -> dict[str, Any]:
    """Pull the useful key/value pairs out of EventData or UserData."""
    out: dict[str, Any] = {}
    data = event.get("EventData")
    if isinstance(data, dict):
        out.update({k: v for k, v in data.items() if not k.startswith("#")})
    user = event.get("UserData")
    if isinstance(user, dict):
        # 1102 nests its fields one level down, e.g. UserData.LogFileCleared.*
        for inner in user.values():
            if isinstance(inner, dict):
                out.update({k: v for k, v in inner.items() if not k.startswith("#")})
    return out


def normalize(record: dict, source_file: str = "") -> Event | None:
    """Turn one pyevtx-rs JSON record into an Event, or None if it isn't watched."""
    data = record.get("data")
    if isinstance(data, str):
        data = json.loads(data)
    event = (data or {}).get("Event", {})
    system = event.get("System", {})
    eid = _event_id(system)
    if eid not in WATCHED_IDS:
        return None
    time_created = system.get("TimeCreated", {})
    ts = (time_created.get("#attributes", {}) or {}).get("SystemTime") or record.get("timestamp", "")
    return Event(
        event_id=eid,
        timestamp=str(ts),
        computer=str(system.get("Computer", "")),
        channel=str(system.get("Channel", "")),
        record_id=record.get("event_record_id"),
        fields=_flatten_data(event),
        source_file=source_file,
    )


def iter_evtx_files(paths: Iterable[str | Path]) -> Iterator[Path]:
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(p.rglob("*.evtx"))
        elif p.suffix.lower() == ".evtx":
            yield p


def read_events(paths: Iterable[str | Path]) -> list[Event]:
    from evtx import PyEvtxParser  # imported here so tests run without real files

    events: list[Event] = []
    for path in iter_evtx_files(paths):
        parser = PyEvtxParser(str(path))
        for record in parser.records_json():
            ev = normalize(record, source_file=path.name)
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e.timestamp)
    return events
