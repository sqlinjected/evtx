This project was submitted to the ryze.ai hackathon by sqlinjected.

# evtx-triage

Offline Windows event log triage that flags attacker activity and explains it in plain English, using small models that run entirely on your machine.

> Submitted to the Ryze AI hackathon (Small Models track). Every model is 500M parameters or fewer and runs locally.

## What it does

Drop in `.evtx` files from a Windows machine and get back the events a responder looks at first:

| Event ID | Log | What it means |
|---|---|---|
| 4625 | Security | Failed logon. Bursts from one source suggest brute force; one source hitting many accounts suggests password spraying. |
| 7045 | System | A new service was installed. Attackers use services for persistence and remote execution (PsExec, etc). |
| 1102 | Security | The Security log was cleared. Almost never legitimate on a production machine. |

Event logs are full of usernames, hostnames and IP addresses, and during an incident the machine may be offline or untrusted. Nothing here sends data anywhere.

## How to run

1. Clone: `git clone https://github.com/sqlinjected/evtx`
2. `cd evtx`
3. Create a virtual environment: `python -m venv .venv`, then activate it (`.venv\Scripts\activate` on Windows, `source .venv/bin/activate` on macOS/Linux)
4. Install: `pip install -e ".[dev]"`
5. Run: `evtx-triage path/to/Security.evtx path/to/System.evtx`
6. JSON output: `evtx-triage samples/ --json > findings.json`

### Generating test data

Never run attack simulations on your real machine. Use a throwaway Windows VM and run [`scripts/generate_test_events.ps1`](scripts/generate_test_events.ps1) from an elevated PowerShell. It produces all three event types and exports the logs to `samples/`.

## The model

Model: sentence-transformers/all-MiniLM-L6-v2 (22M params)
Inference: local, via ONNX Runtime. No external API calls.
License: Apache-2.0

The model scores service names and install paths for how unusual they are, catching cases keyword rules miss.

## Status

- [x] `.evtx` parsing and rule-based baseline detections
- [ ] MiniLM anomaly scoring, compared against the rules baseline
- [ ] Local web UI
- [ ] Demo video

## Dependencies

- [evtx](https://github.com/omerbenamram/pyevtx-rs) (MIT): `.evtx` parsing

## License

MIT. See [LICENSE](LICENSE).
