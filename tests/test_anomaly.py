"""Tests for the scoring logic. They use a tiny fake embedder so they run fast
and never download the real model."""

import hashlib
import re

import numpy as np

from evtx_triage.anomaly import BENIGN, SUSPICIOUS, ServiceScorer, apply, context_hints, describe, leave_one_out
from evtx_triage.cli import main
from evtx_triage.demo import demo_events
from evtx_triage.rules import Finding, run_all


def fake_embed(texts):
    """Bag of path tokens hashed into 256 buckets. Shared tokens mean higher similarity."""
    out = np.zeros((len(texts), 256), dtype=np.float32)
    for i, t in enumerate(texts):
        for tok in re.split(r"[\\/\s\"'.,:]+", t.lower()):
            if tok:
                out[i, int(hashlib.md5(tok.encode()).hexdigest(), 16) % 256] += 1
    return out


def test_reference_sets_are_not_empty_and_distinct():
    assert len(BENIGN) >= 10 and len(SUSPICIOUS) >= 10
    assert not {b[1] for b in BENIGN} & {s[1] for s in SUSPICIOUS}


def test_scores_lean_the_right_way():
    scorer = ServiceScorer(fake_embed)
    bad, good = scorer.score_texts([
        describe("Evil", r"C:\Users\Public\Libraries\evil.exe", "LocalSystem"),
        describe("Fine", r"C:\Windows\System32\spoolsv.exe", "LocalSystem"),
    ])
    assert bad.value > good.value
    assert bad.flagged and not good.flagged


def test_apply_upgrades_low_findings_the_model_flags():
    class Always:
        def score_events(self, events):
            from evtx_triage.anomaly import Score
            return [Score(0.5, "PsExec remote execution", "Print Spooler") for _ in events]

    ev = next(e for e in demo_events() if e.event_id == 7045)
    f = Finding("service_install", "low", "x", [ev])
    assert apply([f], Always()) == 1
    assert f.severity == "medium" and f.anomaly == 0.5 and "missed" in f.note


def test_demo_runs_rules_only(capsys):
    assert main(["--demo", "--no-model"]) == 0
    out = capsys.readouterr().out
    assert "password_spray" in out and "brute_force" in out and "security_log_cleared" in out
    assert "'pat'" not in out  # two typos should stay quiet


def test_demo_findings_cover_every_rule():
    rules = {f.rule for f in run_all(demo_events())}
    assert rules == {"password_spray", "brute_force", "service_install", "security_log_cleared"}


def test_hints_spell_out_paths():
    assert any("Windows root" in h for h in context_hints("mdsync", r"C:\Windows\mdsvc32.exe"))
    assert any("random" in h for h in context_hints("cqzlrwm", r"%COMSPEC% /c x"))
    assert not any("random" in h for h in context_hints("wuauserv", r"C:\Windows\system32\svchost.exe"))
    assert not any("random" in h for h in context_hints("Sysmon64", r"C:\Windows\Sysmon64.exe"))


def test_leave_one_out_counts_every_example():
    r = leave_one_out(fake_embed)
    assert r.total == len(BENIGN) + len(SUSPICIOUS)
    for name, n in r.correct.items():
        assert n + len(r.misses[name]) == r.total
