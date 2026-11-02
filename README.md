# credx

A fast OSINT tool for finding leaked credentials through the [Intelligence X](https://intelx.io/) API. It searches multiple breach databases, extracts credentials from the matched dumps, filters out false positives, and exports deduplicated results as TXT, JSON, or CSV — with resume support so interrupted runs pick up where they left off.

> ⚠️ **For authorized security assessments only.** See [Disclaimer](#disclaimer).

---

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Command-line options](#command-line-options)
- [Extraction modes](#extraction-modes)
- [ML confidence model](#ml-confidence-model-optional)
- [Output formats](#output-formats)
- [Resume](#resume)
- [Features](#features)
- [Troubleshooting](#troubleshooting)
- [Disclaimer](#disclaimer)

---

## Quick start

```bash
# 1. Install
pipx install git+https://github.com/AndreaF17/credx.git

# 2. Add your API key (get one at https://intelx.io/)
echo "INTELX_API_KEY=your_key_here" > .env

# 3. Scan a domain
credx -t example.com
```

That writes deduplicated credentials to `example.com-creds.txt` and prints a color-coded run summary.

---

## Installation

Install with [pipx](https://pipx.pypa.io/) to get the `credx` command on your PATH in an isolated environment:

```bash
# Directly from GitHub
pipx install git+https://github.com/AndreaF17/credx.git

# …or from a local checkout
pipx install .
```

This installs two commands:

| Command | Purpose |
|---|---|
| `credx` | The scanner |
| `credx-train` | Optional trainer for the ML confidence model |

### From source (for development)

```bash
git clone https://github.com/AndreaF17/credx.git
cd credx

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e .
python -m unittest discover -s tests   # run the test suite
```

---

## Configuration

credx needs an Intelligence X API key. Provide it either way:

- **`.env` file** in the directory you run `credx` from:
  ```bash
  INTELX_API_KEY=your_key_here
  ```
- **CLI flag**: `credx -t example.com -k your_key_here`

Get a key at [intelx.io](https://intelx.io/). Never commit your `.env` file.

---

## Usage

```bash
# Basic domain scan  ->  example.com-creds.txt
credx -t example.com

# Scan a specific person's email (auto-enables person-email mode)
credx -t john.doe@example.com

# Choose an output format
credx -t example.com -f json
credx -t example.com -f csv

# Wider net: 12 months back, up to 500 results
credx -t example.com -r 12 -m 500

# Precision vs. recall
credx -t example.com --mode strict        # fewer false positives
credx -t example.com --mode aggressive    # more hits on noisy dumps

# Dig deeper
credx -t example.com --company-wide       # also sweep the bare domain
credx -t example.com --expand-archives    # open multi-file leaks/archives
credx -t example.com --phonebook          # enumerate leaked emails

# Share results with a client, anonymized
credx -t example.com --safe-share

# Speed up with concurrency (watch your rate limits)
credx -t example.com --workers 4 --delay 0.5
```

> **Tip:** Output is colored when writing to a terminal. Set `NO_COLOR=1` to disable it, or `FORCE_COLOR=1` to keep colors when piping to a file or pager.

---

## Command-line options

| Flag | Argument | Default | Description |
|---|---|---|---|
| `-t`, `--target` | `TARGET` | *(required)* | Domain or email to search |
| `-m`, `--maxresults` | `N` | `100` | Max results to return |
| `-k`, `--apikey` | `KEY` | from `.env` | IntelX API key |
| `-o`, `--output` | `FILE` | `<target>-creds.<ext>` | Output file |
| `-f`, `--format` | `txt\|json\|csv` | `txt` | Output format |
| `-r`, `--range` | `MONTHS` | `6` | How far back to search |
| `-d`, `--debug` | | off | Verbose DEBUG logging |
| `-e`, `--email` | | off | For an email target, also search the `@domain` pattern |
| `--company-wide` | | off | For a domain target, also search the bare domain (catches `domain:user:pass`) |
| `--expand-archives` | | off | Walk multi-file leaks (archives/folders) and fetch each child file |
| `--phonebook` | | off | Enumerate leaked selectors to `out/<target>-emails.txt` |
| `--person-name` | `"Full Name"` | | Enrich person-email search terms |
| `--safe-share` | | off | Also write a sanitized CSV safe to share externally |
| `--safe-output` | `FILE` | `out/<output>-safe.csv` | Safe-share output path |
| `--mode` | `strict\|balanced\|aggressive` | `balanced` | Extraction precision/recall |
| `--workers` | `N` | `1` | Concurrent FILE_VIEW workers |
| `--delay` | `SECONDS` | `0.5` | Delay between FILE_VIEW calls (rate limiting) |
| `--model` | `[PATH]` | heuristic | Score with the ML model instead of the heuristic |

Run `credx --help` for the authoritative list.

---

## Extraction modes

Controls how aggressively candidates are kept:

| Mode | Behavior | Use when |
|---|---|---|
| `strict` | Highest precision; drops low-confidence candidates | You want clean results with few false positives |
| `balanced` *(default)* | Sensible middle ground | Most runs |
| `aggressive` | Highest recall | Noisy or non-standard dumps where you'd rather sift manually |

---

## ML confidence model (optional)

By default, each candidate's confidence comes from a hand-tuned heuristic. You can instead score candidates with a trained logistic-regression model that learns which extractions are real credentials versus junk (`admin:admin`, version strings, common passwords) — cases the heuristic tends to over-trust.

The model is **pure standard library** (no scikit-learn, no extra runtime deps) and is stored as an inspectable JSON file of per-feature weights.

```bash
# Train on synthetic data (quick start / demo)
credx-train --synthetic 600

# …or weak-supervise from real dump files
credx-train --input dumps/*.txt --synthetic 200
```

Training writes `models/confidence_model.json` and prints held-out accuracy / precision / recall / F1. Then score with it:

```bash
credx -t example.com --model                 # uses models/confidence_model.json
credx -t example.com --model path/to/model.json
```

With `--model` active, `--mode` becomes a **probability cutoff** (e.g. `strict` keeps only candidates scored ≥ 0.82). If the model file is missing or incompatible, credx logs a warning and falls back to the heuristic. Model artifacts are gitignored — retrain periodically as leak formats drift.

---

## Output formats

**TXT** (default) — one credential per line:
```
https://app.example.com:user@example.com:Password123!
portal.example.com:admin:SecurePass456
```

**JSON** — full metadata per credential:
```json
[
  {
    "url": "https://app.example.com",
    "identity": "user@example.com",
    "email": "user@example.com",
    "password": "Password123!",
    "confidence": 0.97,
    "pattern": "url_delimited",
    "source": "breach_2024_leak.txt"
  }
]
```

**CSV** — same fields as columns:
```csv
url,identity,email,password,source,confidence,pattern,...
https://app.example.com,user@example.com,user@example.com,Password123!,breach_2024_leak.txt,0.97,url_delimited,...
```

### Safe-share export

`--safe-share` produces an anonymized CSV (`TARGET`, `User`, masked `Password`, `Source`) intended for sharing with clients. Customize the path with `--safe-output <file>`.

---

## Resume

Interrupted? Just re-run the same command. credx loads the existing output, skips duplicates, and appends only new findings:

```bash
credx -t example.com   # interrupted
credx -t example.com   # continues where it left off
```

---

## Features

- **Multi-bucket search** across `leaks.private`, `leaks.public`, `leaks.private.li`, and `pastes`
- **Smart deduplication** across all sources, with resume support
- **Flexible extraction** — handles `:`, `;`, `|`, and key/value dumps, plus multiple credentials per line
- **False-positive filtering** with confidence scoring on every match
- **Optional ML scorer** (stdlib logistic regression) for the cases the heuristic over-trusts
- **Person-email targeting** with optional full-name enrichment
- **Safe-share export** for anonymized client reports
- **Concurrent fetching** (`--workers`) with built-in rate limiting and exponential-backoff retries
- **Color-coded output** and a readable end-of-run summary (`NO_COLOR` / `FORCE_COLOR` aware)

---

## Troubleshooting

**`API key is required`**
Ensure `.env` exists with `INTELX_API_KEY=...` in your current directory, or pass `-k`.

**No credentials found**
Try `-e` to broaden the search, widen the range with `-r 12`, add `-d` to see what's being searched, or confirm the target exists in IntelX.

**Rate-limit errors**
credx retries with exponential backoff automatically. Lower `-m`, raise `--delay`, reduce `--workers`, or spread searches over time.

---

## Disclaimer

This tool is for **authorized security assessments only**. Unauthorized access to computer systems is illegal — always obtain proper authorization first. The authors assume no liability for misuse.

---

## Credits

Built on the [Intelligence X API](https://intelx.io/) via the [intelxapi](https://github.com/IntelligenceX/SDK/tree/master/Python) Python SDK.

---

**Star ⭐ this repo if you find it useful!**
