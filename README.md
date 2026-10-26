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
4. Install: `pip install -e ".[ml,dev]"` (drop `ml` for keyword rules only)
5. Try it with no logs at all: `evtx-triage --demo`
6. Run on real logs: `evtx-triage path/to/Security.evtx path/to/System.evtx`
7. JSON output: `evtx-triage samples/ --json > findings.json`
8. Keyword rules only, for comparison: add `--no-model`
9. Accuracy check, model vs rules: `evtx-triage --eval`

The first run with the model downloads about 90 MB of weights to `~/.cache/evtx-triage`. Every run after that works fully offline.

### Generating test data

Never run attack simulations on your real machine. Use a throwaway Windows VM and run [`scripts/generate_test_events.ps1`](scripts/generate_test_events.ps1) from an elevated PowerShell. It produces all three event types and exports the logs to `samples/`.

## The model

- **Model:** [sentence-transformers/all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2), 22M parameters, Apache-2.0
- **Weights:** ONNX export [Qdrant/all-MiniLM-L6-v2-onnx](https://huggingface.co/Qdrant/all-MiniLM-L6-v2-onnx), Apache-2.0
- **Inference:** local, through ONNX Runtime via [fastembed](https://github.com/qdrant/fastembed) (Apache-2.0). No external API calls.

The keyword rules only catch a service install when its path contains a known bad string like `\Users\Public\` or `powershell`. The model is a second opinion on every install.

How it works:

1. Each install path gets a few neutral plain-English notes: where the file lives (Program Files, the system folder, a user profile, a temp folder, a network share), how it launches (command shell, PowerShell, rundll32), and whether the service name looks randomly generated.
2. MiniLM embeds the service name plus those notes. The raw path is left out, because testing showed MiniLM latches onto surface details in raw Windows paths (quotes, length, version numbers), which cut accuracy from 30/35 to 21/35.
3. Each embedding is compared against the average of two short, readable reference lists in [`anomaly.py`](src/evtx_triage/anomaly.py): ordinary software installs, and known attacker tradecraft. Installs closer to the attacker average get flagged.
4. Each finding names the single closest reference example, so the call can be explained.

The model can only add flags, never remove a keyword rule hit. The demo and VM test data are kept out of the reference lists.

## Results

Run `evtx-triage --eval` to reproduce. Each of the 35 reference installs is hidden in turn and classified using the rest (leave-one-out).

| Approach | Correct |
|---|---|
| Keyword rules (baseline) | 29/35 (83%) |
| MiniLM | 30/35 (86%) |
| MiniLM or keyword rules (what the tool does) | 31/35 (89%) |
| The plain-English notes as a hand rule, no model (ablation) | 33/35 (94%) |

What this shows, honestly:

- The model catches things the keyword rules miss: PsExec, RemCom, and random-named binaries in the Windows folder. In the demo it flags both disguised services the rules rate low.
- The ablation beats the model. Most of the signal comes from the plain-English notes, and a simple rule over those notes does better on this set than MiniLM does.
- That ablation is optimistic. The notes were written while looking at these same 35 examples, so a rule over them is partly fit to the test. The model's possible advantage is generalizing to installs the notes do not cover, and 35 examples is too few to show that either way.
- Next step: a larger, held-out set of real 7045 events from different machines, to test whether the model generalizes better than hand rules.

## Status

- [x] `.evtx` parsing and rule-based baseline detections
- [x] MiniLM anomaly scoring for service installs
- [x] `--demo` mode with synthetic events
- [x] Rules vs model comparison, with ablation
- [ ] Local web UI
- [ ] Demo video

## Dependencies

- [evtx](https://github.com/omerbenamram/pyevtx-rs) (MIT): `.evtx` parsing
- [numpy](https://numpy.org) (BSD-3-Clause)
- [fastembed](https://github.com/qdrant/fastembed) (Apache-2.0), optional: local ONNX inference

## License

MIT. See [LICENSE](LICENSE).
