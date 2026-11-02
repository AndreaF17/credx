# credx

A fast OSINT tool for finding leaked credentials through the [Intelligence X](https://intelx.io/) API during penetration tests. Target a **domain**, an **email**, or a **person by name**; credx searches multiple breach databases, extracts credentials from the matched dumps, filters out false positives, and exports deduplicated results as TXT, JSON, CSV, or an interactive **HTML report** — with resume support so interrupted runs pick up where they left off.

> ⚠️ **For authorized security assessments only.** See [Disclaimer](#disclaimer).

---

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [Targeting: domain, email, person](#targeting-domain-email-person)
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

That writes deduplicated credentials to `out/example.com-creds.txt` and prints a color-coded run summary. (All output goes into the `out/` directory.)

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

credx needs an Intelligence X API key. Provide it any of three ways (highest precedence first):

1. **CLI flag**: `credx -t example.com -k your_key_here`
2. **Environment / `.env` file** in the directory you run `credx` from:
   ```bash
   INTELX_API_KEY=your_key_here
   ```
3. **Saved key** managed by credx (stored in `~/.config/credx/config.json`, `0600` permissions):
   ```bash
   credx config set-key your_key_here
   ```

Get a key at [intelx.io](https://intelx.io/). Never commit your `.env` file.

### Managing saved keys

credx can store several keys and switch between them — handy when you work across clients or engagements:

```bash
credx config set-key KEY                 # save as "default" (first key becomes active)
credx config set-key KEY --name client-a # save another key under a name
credx config use client-a                # switch the active key
credx config list                        # list saved keys (masked), * marks the active one
credx config show --name client-a        # show one key (masked)
credx config usage                       # show the active key's IntelX credit usage
credx config clear client-a              # remove one key  (or: --all to remove every key)
```

Pick a saved key for a single run without switching the active one:

```bash
credx -t example.com --key-name client-a
```

Keys are shown masked (`abcd…wxyz`) and never printed in full.

---

## Targeting: domain, email, person

credx auto-detects what you're targeting from `-t` and switches modes:

| Target | Example | What it searches |
|---|---|---|
| **Domain** | `-t corp.com` | The `@corp.com` email selector (add `--company-wide` for host-form creds) |
| **Email** | `-t john.doe@corp.com` | The exact address (add `--usernames` to also try `john.doe` / `john doe` / `johndoe`) |
| **Person (name + domain)** | `-t "John Doe" --domain corp.com` | Name variants, anchored to the domain — **recommended** for people |
| **Person (name only)** | `-t "John Doe"` | Name variants alone — works, but noisy; pair with `--domain` when you can |

A target with a space (e.g. `"John Doe"`), or any non-email target combined with `--domain`, triggers **person-name mode**. With `--domain`, a result must mention both the name and the domain to match, which cuts false positives sharply.

> By default credx searches the last **24 months** — most breach data is older, so widen with `-r` (e.g. `-r 60`) for historical coverage, or narrow it for recency.

---

## Usage

```bash
# Basic domain scan  ->  out/example.com-creds.txt
credx -t example.com

# Scan a specific person's email (auto-enables person-email mode)
credx -t john.doe@example.com

# Hunt a person by name, anchored to their company (recommended)
credx -t "John Doe" --domain example.com

# Broaden an email search to username variants (john.doe, johndoe, …)
credx -t john.doe@example.com --usernames

# Choose an output format
credx -t example.com -f json
credx -t example.com -f csv

# Interactive HTML report (searchable table, masked passwords with reveal)
credx -t example.com -f html

# Deeper history: 5 years back, up to 1000 results (default is 24 months / 500)
credx -t example.com -r 60 -m 1000

# Precision vs. recall
credx -t example.com --mode strict        # fewer false positives
credx -t example.com --mode aggressive    # more hits on noisy dumps

# Dig deeper
credx -t example.com --company-wide       # also sweep the bare domain
credx -t example.com --expand-archives    # open multi-file leaks/archives
credx -t example.com --phonebook          # enumerate leaked emails
credx -t example.com --phonebook-search   # then hunt creds for each discovered email (big recall boost)

# Search deeper: results are paginated automatically — just raise -m
credx -t example.com -m 2000

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
| `-t`, `--target` | `TARGET` | *(required)* | Domain, email, or person name to search |
| `-m`, `--maxresults` | `N` | `500` | Max results to return |
| `-k`, `--apikey` | `KEY` | from env/saved | IntelX API key (overrides env var and saved key) |
| `--key-name` | `NAME` | active key | Use a saved key by name for this run (see `credx config`) |
| `-o`, `--output` | `FILE` | `<target>-creds.<ext>` | Output file |
| `-f`, `--format` | `txt\|json\|csv\|html` | `txt` | Output format |
| `-r`, `--range` | `MONTHS` | `24` | How far back to search |
| `-d`, `--debug` | | off | Verbose DEBUG logging |
| `-e`, `--email` | | off | For an email target, also search the `@domain` pattern |
| `--domain` | `corp.com` | | Anchor a person-name target to a company domain |
| `--usernames` | | off | For an email target, also search username/local-part variants |
| `--company-wide` | | off | For a domain target, also search the bare domain (catches `domain:user:pass`) |
| `--expand-archives` | | off | Walk multi-file leaks (archives/folders) and fetch each child file |
| `--phonebook` | | off | Enumerate leaked selectors to `out/<target>-emails.txt` |
| `--phonebook-search` | | off | Hunt credentials for each discovered email on the target domain (implies `--phonebook`). Big recall boost, many extra API calls |
| `--phonebook-max` | `N` | `0` | Cap how many discovered emails `--phonebook-search` hunts (`0` = no cap) |
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
    "secret_type": "plaintext",
    "confidence": 0.97,
    "pattern": "url_delimited",
    "source": "breach_2024_leak.txt"
  }
]
```

`secret_type` is `plaintext` or the detected hash type (`md5`, `sha1`, `sha256`, `sha512`, `bcrypt`, `argon2`, `md5crypt`, `sha256crypt`, `sha512crypt`, `phpass`).

**CSV** — same fields as columns:
```csv
url,identity,email,password,secret_type,date,source,confidence,pattern,...
https://app.example.com,user@example.com,user@example.com,Password123!,plaintext,2024-05-01,breach_2024_leak.txt,0.97,url_delimited,...
```

**HTML** (`-f html`) — a self-contained, interactive report (`out/<target>-creds.html`):

- Searchable, sortable table of every credential, with a **Type** column (plaintext vs. hash)
- Passwords **masked by default**; click a password or toggle **Reveal passwords** to show them
- Confidence color-coding, light/dark theme, no external dependencies — just open it in a browser
- Resumable like JSON/CSV: records are embedded in the page, so re-runs accumulate and dedup

### Safe-share export

`--safe-share` produces an anonymized CSV (`TARGET`, `User`, masked `Password`, `Type`, `Date`, `Source`) intended for sharing with clients — the `Type` column flags whether each masked secret was plaintext or a hash. Customize the path with `--safe-output <file>`.

---

## Resume

Interrupted? Just re-run the same command. credx loads the existing output, skips duplicates, and appends only new findings:

```bash
credx -t example.com   # interrupted
credx -t example.com   # continues where it left off
```

---

## Features

- **Multi-bucket search** across `leaks.private`, `leaks.public`, `leaks.private.li`, and `pastes`, paginated automatically up to `-m`
- **Smart deduplication** across all sources, with resume support
- **Flexible extraction** — handles `:`, `;`, `|`, and key/value dumps, plus multiple credentials per line
- **Structured-dump parsing** — reads SQL `INSERT` statements, JSON/NDJSON exports, and header-named CSV (where the credential columns are named), not just delimited combolists
- **Multi-key management** — save, name, switch and inspect multiple IntelX keys (`credx config`), with per-key credit-usage reporting
- **Password-hash detection** — tags each secret as plaintext or a hash type (MD5, SHA-1/256/512, bcrypt, argon2, md5crypt…), so you know what you're cracking
- **False-positive filtering** with confidence scoring on every match
- **Optional ML scorer** (stdlib logistic regression) for the cases the heuristic over-trusts
- **Domain, email, and person-name targeting** — hunt a person by name, anchored to their company domain
- **Phonebook-driven recall** — enumerate a domain's leaked emails, then hunt credentials for each (`--phonebook-search`)
- **Interactive HTML report** with masked passwords, a hash-type column, search, and sorting
- **Safe-share export** for anonymized client reports
- **Concurrent fetching** (`--workers`) with built-in rate limiting and exponential-backoff retries
- **Color-coded output** and a readable end-of-run summary (`NO_COLOR` / `FORCE_COLOR` aware)

---

## Troubleshooting

**`API key is required`**
Save one with `credx config set-key <KEY>`, or ensure `.env` has `INTELX_API_KEY=...` in your current directory, or pass `-k`.

**No credentials found**
Try `-e` to broaden the search, widen the range with `-r 60`, raise `-m` to page deeper, add `--phonebook-search` to hunt every leaked email on the domain, add `-d` to see what's being searched, or confirm the target exists in IntelX.

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
