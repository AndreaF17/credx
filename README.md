# credx

A fast OSINT tool for searching leaked credentials using the Intelligence X API. Searches across multiple breach databases and exports results in TXT, JSON, or CSV formats with built-in deduplication and resume capability.

## Features

✅ **Multi-bucket search** - Searches `leaks.private`, `leaks.public`, `leaks.private.li`, and `pastes`  
✅ **Smart deduplication** - Prevents duplicate credentials across multiple sources  
✅ **Resume capability** - Continue interrupted searches without re-downloading  
✅ **Multiple output formats** - TXT, JSON, or CSV export  
✅ **Rate limiting & retry logic** - Handles API throttling with exponential backoff  
✅ **Credential validation** - Filters out false positives using regex patterns  
✅ **Flexible extraction** - Supports `:`, `;`, `|`, and key/value credential dumps  
✅ **Extraction modes** - `strict`, `balanced`, `aggressive` for precision/recall control  
✅ **Confidence scoring** - Every match includes parser pattern + confidence score  
✅ **Optional ML model** - Train a stdlib logistic-regression scorer to filter false positives the heuristic over-trusts  
✅ **Concurrent fetching** - Optional `--workers` for bounded-parallel leak downloads with rate limiting  
✅ **Multi-hit line parsing** - Extracts multiple credentials from a single leak line  
✅ **Person-email targeting** - Expands search terms and matches specifically for a person email  
✅ **Safe-share export** - Optional anonymized CSV output for external clients  
✅ **Colored logging** - INFO/DEBUG modes with intuitive color-coded output  
✅ **Regex injection safe** - Properly escapes search patterns  

## Installation

Install with [pipx](https://pipx.pypa.io/) to get the `credx` command on your PATH
in an isolated environment:

```bash
# From a local checkout
pipx install .

# Or directly from GitHub
pipx install git+https://github.com/AndreaF17/credx.git
```

This installs two commands: `credx` (the scanner) and `credx-train` (the optional
confidence-model trainer).

### From source (for development)

```bash
git clone https://github.com/AndreaF17/credx.git
cd credx

python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

pip install -e .
```

## Configuration

### API Key Setup

Create a `.env` file in the directory you run `credx` from:

```bash
INTELX_API_KEY=your_api_key_here
```

Or pass the API key via command line with `-k` flag.

Get your API key from: [https://intelx.io/](https://intelx.io/)

## Usage

### Basic Usage

```bash
# Search for domain credentials (creates domain.com-creds.txt)
credx -t domain.com

# Search with email pattern enabled
credx -t domain.com -e

# Search for a specific person email target
credx -t john.doe@example.com

# Specify output format
credx -t domain.com -f csv
credx -t domain.com -f json
```

### Advanced Options

```bash
# Custom date range (12 months) and max results
credx -t domain.com -r 12 -m 500

# More recall on noisy dumps
credx -t domain.com --mode aggressive

# Higher precision mode
credx -t domain.com --mode strict

# Enrich person-email searches with full name terms
credx -t john.doe@example.com --person-name "John Doe"

# Also sweep the bare company name (not just @domain) for host-form creds
credx -t domain.com --company-wide

# Fetch files inside multi-file leaks (archives/stealer-log folders)
credx -t domain.com --expand-archives

# Enumerate leaked emails/selectors via Phonebook (-> out/domain.com-emails.txt)
credx -t domain.com --phonebook

# Create an anonymized safe-share file
credx -t domain.com --safe-share

# Custom name/path for safe-share file
credx -t domain.com --safe-output client-report.csv

# Enable debug logging
credx -t domain.com -d

# Custom output file
credx -t domain.com -o results.txt

# Provide API key via CLI
credx -t domain.com -k YOUR_API_KEY
```

### Full Command Reference

```
usage: credx [-h] -t TARGET [-m MAXRESULTS] [-k APIKEY] [-o OUTPUT]
               [-f {txt,json,csv}] [-r RANGE] [-d] [-e]
               [--person-name PERSON_NAME]
               [--safe-share] [--safe-output SAFE_OUTPUT]
               [--mode {aggressive,balanced,strict}]

Search for leaked credentials

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target to search (domain or email)
  -m MAXRESULTS, --maxresults MAXRESULTS
                        Maximum number of results per bucket (default: 100)
  -k APIKEY, --apikey APIKEY
                        IntelX API key
  -o OUTPUT, --output OUTPUT
                        Output file to save the results
  -f {txt,json,csv}, --format {txt,json,csv}
                        Output format (default: txt)
  -r RANGE, --range RANGE
                        Search range in months (default: 6)
  -d, --debug           Enable DEBUG logging
  -e, --email           Also search for @domain pattern
  --person-name PERSON_NAME
                        Optional full name to enrich person-email search
                        terms
  --safe-share          Generate a sanitized CSV file safe to share with
                        external clients
  --safe-output SAFE_OUTPUT
                        Optional safe-share output filename (default:
                        out/<output>-safe.csv)
  --mode {aggressive,balanced,strict}
                        Extraction mode: strict (precision), balanced
                        (default), aggressive (recall)
```

### Extraction Modes

- **strict**: highest precision, drops low-confidence candidates
- **balanced**: recommended default for most runs
- **aggressive**: highest recall on noisy/non-standard dumps

### ML Confidence Model (optional)

By default, each candidate's confidence is computed by a hand-tuned heuristic.
You can optionally score candidates with a trained logistic-regression model
instead — it learns from data which extractions are real credentials versus
junk (e.g. `admin:admin`, version strings, common passwords), which the
heuristic tends to over-trust.

The model is **pure standard library** (no scikit-learn, no new runtime deps)
and is serialized as an inspectable JSON list of per-feature weights.

Train a model:

```bash
# Self-contained: train on synthetic labeled data (good for a quick start/demo)
credx-train --synthetic 600

# Or weak-supervise from real dump files (labels bootstrapped from high-confidence
# heuristic hits; trivial/ambiguous candidates handled automatically)
credx-train --input dumps/*.txt --synthetic 200
```

This writes `models/confidence_model.json` and prints held-out
accuracy/precision/recall/F1. Then score with it:

```bash
# Bare flag uses models/confidence_model.json
credx -t domain.com --model

# Or point at a specific model file
credx -t domain.com --model path/to/model.json
```

When `--model` is active, the `--mode` threshold is interpreted as a
**probability cutoff** (e.g. `strict` keeps only candidates the model scores
≥ 0.82). If the model file is missing or incompatible, the scanner logs a
warning and falls back to the heuristic. Trained model artifacts are gitignored;
retrain periodically as leak formats drift.

### Person Target Search

- If `--target` is an email address, the scanner automatically enables person-email mode.
- By default, person-email mode searches only the exact full email address.
- It does not automatically search only the local-part (e.g. `info` from `info@example.it`).
- Use `--person-name` to explicitly enrich search terms when you want broader recall.
- Use `-e` if you explicitly want the broader `@domain` email-pattern search.

### Safe-Share Export

- Add `--safe-share` to automatically produce an anonymized CSV for clients.
- Add `--safe-output <filename>` to customize the safe-share file path/name.
- The safe-share file includes `TARGET`, `User`, masked `Password`, and `Source`.

## Output Formats

### TXT Format (default)
```
https://app.example.com:user@example.com:Password123!
portal.example.com:admin:SecurePass456
```

### JSON Format
```json
[
  {
    "url": "https://app.example.com",
    "identity": "user@example.com",
    "email": "user@example.com",
    "password": "Password123!",
    "confidence": 0.97,
    "pattern": "url_delimited",
    "canonical": "https://app.example.com:user@example.com:Password123!",
    "raw_line": "https://app.example.com:user@example.com:Password123!",
    "source": "breach_2024_leak.txt"
  }
]
```

### CSV Format
```csv
url,identity,email,password,source,confidence,pattern,canonical,raw_line
https://app.example.com,user@example.com,user@example.com,Password123!,breach_2024_leak.txt,0.97,url_delimited,https://app.example.com:user@example.com:Password123!,https://app.example.com:user@example.com:Password123!
```

## Resume Capability

If the script is interrupted, simply re-run the same command. It will:
1. Load existing credentials from the output file
2. Skip duplicates automatically
3. Append only new findings

```bash
# First run (interrupted)
credx -t domain.com

# Resume (continues where it left off)
credx -t domain.com
```

## Logging

**INFO mode (default):**
- Search parameters
- Found credentials
- Total unique count

**DEBUG mode (`-d` flag):**
- API initialization details
- Per-bucket search results
- Individual leak processing
- Duplicate detection
- FILE_VIEW retry attempts
- Skip reasons (`no valid credential pattern` / `low confidence` / `target mismatch`)
- End-of-run extraction statistics

## Best Practices

1. **Start with small date ranges** - Test with `-r 1` for one month
2. **Use email search judiciously** - `-e` flag increases API calls significantly
3. **Monitor rate limits** - The script includes 0.5s delays between requests
4. **Check output regularly** - Use resume capability for large searches
5. **Secure your API key** - Never commit `.env` file to version control

## Limitations

- IntelX API rate limits apply
- Free tier has limited daily requests
- Password validation expects either `url:email:password` or `url:username:password`
- TLD must be 2+ characters for credential matching

## Troubleshooting

**"API key is required" error:**
- Check `.env` file exists and contains `INTELX_API_KEY=...`
- Or provide key with `-k` flag

**No credentials found:**
- Try enabling email search with `-e`
- Increase date range with `-r 12`
- Enable debug mode with `-d` to see what's being searched
- Verify the domain exists in IntelX database

**Rate limit errors:**
- Script automatically retries with exponential backoff
- Reduce `maxresults` with `-m 50`
- Consider spreading searches over multiple days

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Disclaimer

This tool is for **authorized security assessments only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

The authors assume no liability for misuse of this tool.

## Credits

- Built with [Intelligence X API](https://intelx.io/)
- Uses [intelxapi](https://github.com/IntelligenceX/SDK/tree/master/Python) Python SDK

## Support

For issues, feature requests, or questions:
- Open an issue on GitHub
- Check existing issues for solutions

---

**Star ⭐ this repo if you find it useful!**
