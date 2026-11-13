# evtx-triage

Offline Windows event log triage. It flags attacker activity and explains each finding in plain English, using small models that run on your own machine.

> Submitted to the Ryze AI hackathon (Small Models track). Every model is 500M parameters or fewer and runs locally.

## Why I built this

My background is digital forensics and pulling evidence off devices. Most log triage tools assume you already know what you're looking at. I wanted something simple that runs locally, takes a couple of log files, and tells you what matters and why.

## What it does

Drop in `.evtx` files from a Windows machine and get back the events a responder looks at first:

| Event ID | Log | What it means |
|---|---|---|
| 4625 | Security | Failed logon. Bursts from one source suggest brute force. One source hitting many accounts suggests password spraying. |
| 7045 | System | A new service was installed. Attackers use services for persistence and remote execution (PsExec, etc). |
| 1102 | Security | The Security log was cleared. Almost never legitimate on a production machine. |

Event logs are full of usernames, hostnames and IP addresses, and during an incident the machine may be offline or untrusted. Nothing here sends data anywhere.

## How to run

```
git clone https://github.com/sqlinjected/evtx
cd evtx
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[ml,dev]"

evtx-triage --demo                      # no logs needed
evtx-triage Security.evtx System.evtx   # real logs
evtx-triage --eval                      # model vs rules
```

On macOS/Linux activate with `source .venv/bin/activate`. Add `--json` for JSON output, or `--no-model` for keyword rules only (you can also drop `ml` from the install).

The first run with the model downloads about 90 MB of weights to `~/.cache/evtx-triage`. After that it works fully offline.

### Generating test data

Don't run attack simulations on your real machine. Use a throwaway Windows VM and run [`scripts/generate_test_events.ps1`](scripts/generate_test_events.ps1) from an elevated PowerShell. It produces all three event types and exports the logs to `samples/`.

## The model

I use [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2) (22M parameters, Apache-2.0), with the [ONNX export from Qdrant](https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx), running locally through ONNX Runtime via [fastembed](https://github.com/qdrant/fastembed). No external API calls.

The keyword rules only catch a service install when its path contains a known bad string like `\Users\Public\` or `powershell`. The model is a second opinion on every install.

1. Each install path gets a few plain-English notes: where the file lives (Program Files, the system folder, a user profile, a temp folder, a network share), how it launches (command shell, PowerShell, rundll32), and whether the service name looks randomly generated.
2. MiniLM embeds the service name plus those notes. I leave the raw path out. When I tested with raw paths, MiniLM latched onto surface details like quotes, length and version numbers, and accuracy dropped from 30/35 to 21/35.
3. Each embedding is compared against the average of two short reference lists in [`anomaly.py`](src/evtx_triage/anomaly.py): ordinary software installs, and known attacker tradecraft.