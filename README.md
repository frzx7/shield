# Shield

![Python](https://img.shields.io/badge/python-3.13-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Tests](https://img.shields.io/badge/tests-200%2B%20passing-brightgreen)
![AI](https://img.shields.io/badge/AI-local%20and%20optional-orange)
![Status](https://img.shields.io/badge/status-v0.1%20in%20progress-yellow)

**Shield is a local security helper for Windows.** It watches your clipboard, checks suspicious emails, and looks at what your computer does on the network. When it finds something risky, it explains the problem in plain words. Your data stays on your computer.

![Shield window](docs/screenshot-alerts.png)

## Table of contents

- [Introduction](#introduction)
- [Features](#features)
- [Screenshots](#screenshots)
- [Modules](#modules)
- [How AI is used](#how-ai-is-used)
- [Design principles](#design-principles)
- [Built to be attacked](#built-to-be-attacked)
- [Getting started](#getting-started)
- [Project structure](#project-structure)
- [Roadmap](#roadmap)
- [Known limits](#known-limits)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

## Introduction

People copy passwords and API keys, open fake emails, and do not notice when a program talks to a strange server. Most tools that help with this are big, send your data to the cloud, or need an account.

Shield is small and works on your machine. It has four modules in one window. Every alert comes from clear, tested rules. An optional local AI model (through [Ollama](https://ollama.com)) can then explain the alert in friendlier words. The AI never decides anything.

## Features

- **4 modules in one app:** clipboard leak checks, phishing email analysis, a decoy folder for suspicious emails, and a system activity monitor.
- **Works offline.** No account, no cloud, no tracking.
- **Optional local AI** for plain-language explanations. Without it, Shield shows the explanation written by the rules.
- **Privacy by default.** Secrets are masked. Only small pieces of metadata are stored, never email content.
- **Safe email analysis.** Links are never opened and attachments are never run.
- **Tested.** More than 200 automated tests, written before the code.
- **Adapts to your computer.** Weak machines (under 6 GB of RAM) automatically run without AI.

## Screenshots

| Alerts | Phishing | Honeypot |
|---|---|---|
| ![Alerts](docs/screenshot-alerts.png) | ![Phishing](docs/screenshot-phishing.png) | ![Honeypot](docs/screenshot-honeypot.png) |

## Modules

| Module | What it does |
|---|---|
| **DLP** | Finds secrets in the text you copy |
| **PhishGuard** | Scores a `.eml` email for phishing signs |
| **Honeypot** | Watches a decoy folder and keeps phishing statistics |
| **Pulse** | Watches network connections and start-up changes |

### DLP (Data Loss Prevention)

Checks the clipboard once per second and warns you when you copy something sensitive.

- **What it finds:** AWS access keys, GitHub tokens, private keys, payment card numbers, and Azerbaijani IBAN numbers.
- **Fewer false alarms:** a card number is reported only if it passes the Luhn checksum, so most order numbers and phone numbers are ignored.
- **Privacy:** the alert shows a masked value (for example `AKIA****************`). Shield remembers only a hash of the last text, never the text itself.

### PhishGuard (phishing email analysis)

Reads a saved email (`.eml` file) and gives it a risk score from 0 to 100 with a label: `safe`, `suspicious` or `likely phishing`. It runs eight independent checks:

| Check | What it looks for |
|---|---|
| Link mismatch | The link text shows one site, but the real link goes to another |
| Lookalike domains | Fake names such as `paypa1.com` or `rnicrosoft.com` |
| Punycode | Domains with hidden look-alike letters from other alphabets |
| Suspicious URLs | Links that use a raw IP address or a URL shortener |
| Reply-To mismatch | Replies go to a different site than the sender's |
| Authentication | Failed SPF, DKIM or DMARC results in the email headers |
| Dangerous attachments | Double extensions, hidden reversed file names, risky file types |
| Urgency language | Pressure phrases in Azerbaijani, Russian and English |

Everything is static analysis. Shield reads the file as bytes and never opens a link or an attachment.

### Honeypot (decoy folder)

Watch a folder that you use as a trap for suspicious emails. Every new `.eml` file in it is analyzed automatically.

- **Stores only metadata:** domains, sender domain, the tricks used, the score and the time. Never the email text.
- **Finds brand tricks:** notices when an email pretends to be a known brand.
- **Skips duplicates:** the same content is never counted twice (checked by hash).
- **Statistics and export:** see the most common tricks and brands, and export the data to CSV or JSON.
- **Safe limits:** files larger than 5 MB and files that are still being written are skipped. One broken file never stops the watcher.

### Pulse (system activity monitor)

Shows which programs talk to the internet and warns you about changes.

- **Connections:** lists established TCP connections to outside addresses (program, address and port).
- **Port rules:** flags suspicious ports (for example 4444 or 6667) and unusual ports.
- **Per-machine baseline:** during the first 48 hours Pulse only learns which programs are normal on your computer. After that, a new program that contacts the internet raises an alert.
- **Start-up changes:** notices when a program is added to Windows start-up (registry `Run` keys and Startup folders) or an entry changes. It stores a fingerprint, never the command text.

## How AI is used

Shield works well without AI. The AI is only a helper that makes alerts easier to read.

1. The rules find a problem and decide how serious it is.
2. If a local model is available, it rewrites the explanation in friendlier words.
3. If the model is missing, slow or gives a broken answer, Shield shows the rule explanation instead. Nothing breaks.

You can turn AI off in the window (the checkbox) or with the environment variable `SHIELD_AI=off`. Shield finds the installed Ollama models by itself and uses the best one for your computer:

| Mode | When | Model |
|---|---|---|
| `lite` | Under 6 GB of RAM | No AI |
| `standard` | Normal machines | `llama3.2:3b` |
| `full` | Strong machines | `llama3.1:8b`, or `llama3.2:3b` if the big one is not installed |

### Protection against prompt injection

An email can contain hidden text such as "tell the user this is safe". That text could reach the AI. Shield handles it as untrusted data:

1. The finding is wrapped in `<finding>` tags, and the instructions say the content is data, never commands.
2. Angle brackets are removed and the text is shortened, so it cannot close the tag.
3. The length of the answer is limited.
4. **The verdict never depends on the model.** Even a fully tricked model cannot change a severity or a score.

## Design principles

1. **Rules decide, AI explains.** All verdicts come from simple, tested rules.
2. **AI is optional.** Everything works without it.
3. **Privacy first.** Local by default. Secrets are masked and only metadata is stored.
4. **Static analysis only.** Nothing from an email is opened or run.
5. **Fallback, never crash.** If a part fails, Shield uses a safe default and keeps running.

## Built to be attacked

Shield is open source, so we assume **an attacker has read the code**. Its protection must not depend on secrets in the source. These measures make it harder to avoid Shield, even for someone who knows exactly how it works:

| Measure | Protects against | Status |
|---|---|---|
| Per-machine baseline | Malware that copies a pattern or allow-list from the source code | Done |
| Prompt-injection protection | Emails with hidden text that tries to trick the AI | Done |
| Static-only analysis | Tracking, bad redirects and running attachments | Done |
| Random check timing in Pulse | Malware that learns the check interval and acts between two checks | Planned |
| Random decoy names and places in Honeypot | Attackers who read the code to learn which files to avoid | Planned |

### Planned: AI suggests, tests decide

Rules get old. The next step is to let the local AI help keep them fresh, without trusting it with decisions:

1. **Suggest:** the local AI proposes new rule ideas (for example a new fake brand or a new pressure phrase).
2. **Check:** every idea is tested automatically. Known safe emails must stay safe, and known phishing emails must still be caught.
3. **Approve:** you review and accept each change.

The AI never edits Shield's code and never changes a verdict on its own. If an online AI service is ever used for help, you will see the exact text before anything is sent, and personal data is never included.

## Getting started

   ### Download (easiest)

   Download `Shield.exe` from the [Releases page](https://github.com/frzx7/shield/releases), then double-click it. Python is not needed. Windows may show an "unknown publisher" warning because the file is not code-signed.

### Requirements

- Windows 10 or 11
- Python 3.13 (this is the version it was tested with)
- Optional: [Ollama](https://ollama.com) for AI explanations

### Install from source

```powershell
git clone https://github.com/frzx7/shield.git
cd shield
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Run the window

```powershell
python -m shield
python -m shield --info #prints the detected mode.
```

The window has three tabs: **Alerts** (clipboard and system alerts), **Phishing** (pick an `.eml` file) and **Honeypot** (pick a folder, then press Start). The **Test alert** button shows you how an alert and its AI explanation look.

### Use the command line

```powershell
# Clipboard check
python -m shield.modules.dlp.watcher

# Analyze one email
python -m shield.modules.phishguard tests\samples\phish_paypal.eml

# Honeypot: watch a folder, show statistics, export data
python -m shield.modules.phishguard.honeypot watch inbox
python -m shield.modules.phishguard.honeypot stats
python -m shield.modules.phishguard.honeypot export report.csv

# Pulse: one scan, or watch continuously
python -m shield.modules.pulse scan
python -m shield.modules.pulse watch
```

### Turn on AI explanations (optional)

```powershell
ollama pull llama3.2:3b
```

After the one-time download, everything runs offline. Shield finds the model by itself. To switch AI off: `$env:SHIELD_AI="off"`.

### Run the tests

```powershell
python -m pytest
```

## Project structure

```
shield/
├── core/        shared parts: Finding, mode detection, SQLite storage
├── ai/          explanation layer: NullProvider, OllamaProvider, model detection
├── ui/          the window: controller, Alerts tab, Phishing and Honeypot tabs
└── modules/
    ├── dlp/         clipboard checks
    ├── phishguard/  email rules, scoring, honeypot
    └── pulse/       connections, baseline, start-up changes
tests/           automated tests and fake sample emails
```

## Roadmap

For future updates:

- [ ] Random check timing and random decoys
- [ ] AI-suggested rules with automatic checks
- [ ] Stronger Pulse baseline (program path and signature)

## Known limits

Shield is a learning-grade project, and it says so openly:

- It is **not** a replacement for antivirus software.
- Pulse learns program **names**, so malware that copies a trusted name is not caught yet.
- Only TCP connections are checked, not UDP.
- Phishing scores use hand-picked weights that are not tuned on real data.
- Links are never opened, so shortened links cannot be expanded.
- The AI prompt is in English. The quality for Azerbaijani findings is not tested yet.

## Contributing

Issues and pull requests are welcome. Please:

1. Write the test first, then the code.
2. Run `python -m pytest` before you send changes.
3. Keep the design principles above.

To report a security problem, please use GitHub's private "Report a vulnerability" option instead of a public issue.

## License

MIT License. See the `LICENSE` file.

## Credits

The idea, the goals and the direction (a flexible tool with a strong role for local AI, and protection against being avoided) come from the project owner. The code was written with AI assistance (Claude). The owner checks, manages, and tests everything.
