#!/usr/bin/env python3
"""IntelX credential scanner.

Searches the Intelligence X API for leaked credentials matching a target
(domain or email), extracts candidate credentials from the matched leak
files, and writes deduplicated results to disk (txt/json/csv) with an
optional sanitized "safe-share" CSV.

All logic lives in importable, unit-testable functions; the CLI entry
point is ``main()``, guarded by ``if __name__ == '__main__'``.
"""
from __future__ import annotations

import argparse
import csv
import importlib
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

import colorlog
from dateutil.relativedelta import relativedelta
from dotenv import load_dotenv

from custom.credential_extractor import (
    DEFAULT_MODE,
    EXTRACTION_MODES,
    build_person_email_context,
    build_search_terms,
    build_target_context,
    candidate_mentions_person_email,
    candidate_mentions_target,
    extract_credentials_from_line,
    is_email_target,
)
from custom.confidence_model import DEFAULT_MODEL_PATH, ConfidenceModel
from custom.parser import anonymize_password, parse_line_candidates

# Optional progress bar; the scanner degrades gracefully without it.
try:  # pragma: no cover - exercised indirectly
    from tqdm import tqdm as _tqdm
except ImportError:  # pragma: no cover
    _tqdm = None


# ── Configuration ────────────────────────────────────────────────────────────
# Buckets searched on IntelX, in priority order.
BUCKETS: Tuple[str, ...] = ('leaks.private', 'leaks.public', 'leaks.private.li', 'pastes')

# Maximum retries for FILE_VIEW API calls.
MAX_RETRIES: int = 3
# Seconds before the first retry; doubles after each attempt (exponential backoff).
RETRY_DELAY: float = 2.0
# Default seconds between FILE_VIEW calls (rate limiting). Overridable with --delay.
REQUEST_DELAY: float = 0.5
# Default number of concurrent FILE_VIEW workers. 1 preserves legacy sequential behavior.
DEFAULT_WORKERS: int = 1
# Default search range in months.
DEFAULT_RANGE_MONTHS: int = 6
# Default maximum results requested PER (search term, bucket) pair. IntelX stops
# at this cap, so a low value silently truncates results for large domains; raise
# it (at the cost of more rate-limited FILE_VIEW fetches) when coverage matters.
DEFAULT_MAX_RESULTS: int = 500

# Per-mode minimum confidence thresholds live in credential_extractor.EXTRACTION_MODES;
# they are the single source of truth for confidence defaults (see --mode).


@dataclass(frozen=True)
class RetryConfig:
    """Retry/backoff parameters for FILE_VIEW calls."""

    max_retries: int = MAX_RETRIES
    retry_delay: float = RETRY_DELAY


# Errors we expect from network/IO/SDK calls and can recover from on a per-leak
# basis. Anything outside this set is genuinely unexpected and is allowed to
# surface so it isn't silently swallowed.
try:  # pragma: no cover - import availability is environment dependent
    import requests as _requests

    _NETWORK_ERRORS: Tuple[type, ...] = (_requests.exceptions.RequestException,)
except ImportError:  # pragma: no cover
    _NETWORK_ERRORS = ()

EXPECTED_LEAK_ERRORS: Tuple[type, ...] = (OSError, ValueError, KeyError, TypeError) + _NETWORK_ERRORS


def load_intelx_client() -> Optional[Any]:
    """Load the IntelX client constructor from available SDK package names."""
    for module_name in ('intelxapi', 'intelx'):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue

        client = getattr(module, 'intelx', None)
        if client is not None:
            return client
    return None


# ── Argument parsing & logging ───────────────────────────────────────────────
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments. ``argv`` defaults to ``sys.argv[1:]``."""
    parser = argparse.ArgumentParser(description='Search for leaked credentials')
    parser.add_argument('-t', '--target', type=str, help='Target to search (domain or email)', required=True)
    parser.add_argument('-m', '--maxresults', type=int, help='Maximum number of results to return', default=DEFAULT_MAX_RESULTS)
    parser.add_argument('-k', '--apikey', type=str, help='IntelX API key', required=False)
    parser.add_argument('-o', '--output', type=str, help='Output file to save the results', default=None)
    parser.add_argument('-f', '--format', type=str, choices=['txt', 'json', 'csv'], help='Output format (txt, json, csv)', default='txt')
    parser.add_argument('-r', '--range', type=int, help='Search range in months', default=DEFAULT_RANGE_MONTHS)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable DEBUG logging (default: INFO)')
    parser.add_argument(
        '-e', '--email', action='store_true',
        help='For an email target, also search the @domain pattern. '
             '(Domain targets already search @domain by default.)',
    )
    parser.add_argument(
        '--company-wide', action='store_true',
        help='For a domain target, also search the bare domain (not just @domain). '
             'Catches host-form creds (domain:user:pass) at the cost of fetching '
             'more business-data documents, which the extractor then filters out.',
    )
    parser.add_argument(
        '--expand-archives', action='store_true',
        help='Walk multi-file leaks (archives/folders) via the treeview and fetch '
             'each child file, so credentials inside bundles are not missed. '
             'Adds one treeview + extra FILE_VIEW calls per container.',
    )
    parser.add_argument(
        '--phonebook', action='store_true',
        help='Also run an IntelX Phonebook search to enumerate leaked selectors '
             '(emails/domains) for the target, written to out/<target>-emails.txt.',
    )
    parser.add_argument(
        '--person-name',
        type=str,
        default=None,
        help='Optional full name to enrich person-email search terms',
    )
    parser.add_argument(
        '--safe-share',
        action='store_true',
        help='Generate a sanitized CSV file safe to share with external clients',
    )
    parser.add_argument(
        '--safe-output',
        type=str,
        default=None,
        help='Optional safe-share output filename (default: out/<output>-safe.csv)',
    )
    parser.add_argument(
        '--mode',
        type=str,
        choices=sorted(EXTRACTION_MODES.keys()),
        default=DEFAULT_MODE,
        help='Extraction mode: strict (precision), balanced (default), aggressive (recall)',
    )
    parser.add_argument(
        '--workers',
        type=int,
        default=DEFAULT_WORKERS,
        help='Number of concurrent FILE_VIEW workers (default: 1, sequential)',
    )
    parser.add_argument(
        '--delay',
        type=float,
        default=REQUEST_DELAY,
        help=f'Seconds between FILE_VIEW calls for rate limiting (default: {REQUEST_DELAY})',
    )
    parser.add_argument(
        '--model',
        nargs='?',
        const=DEFAULT_MODEL_PATH,
        default=None,
        help='Score candidates with the trained ML confidence model instead of the heuristic. '
             f'Bare flag uses {DEFAULT_MODEL_PATH}; pass a path to use another. '
             'The --mode threshold is then applied as a probability cutoff.',
    )

    args = parser.parse_args(argv)

    # --safe-output implies --safe-share.
    if args.safe_output and not args.safe_share:
        args.safe_share = True

    if args.workers < 1:
        parser.error('--workers must be >= 1')
    if args.delay < 0:
        parser.error('--delay must be >= 0')

    return args


# ── Terminal colors ───────────────────────────────────────────────────────────
_ANSI = {
    'reset': '\033[0m', 'bold': '\033[1m', 'dim': '\033[2m',
    'red': '\033[31m', 'green': '\033[32m', 'yellow': '\033[33m',
    'blue': '\033[34m', 'magenta': '\033[35m', 'cyan': '\033[36m',
}


def color_enabled(stream: Any = None) -> bool:
    """Whether ANSI colors should be emitted.

    Honors ``NO_COLOR`` (disable) and ``FORCE_COLOR`` (enable) env vars, and
    otherwise only colors when writing to an interactive terminal.
    """
    stream = stream or sys.stderr
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('FORCE_COLOR'):
        return True
    return bool(getattr(stream, 'isatty', lambda: False)())


def colorize(text: Any, *styles: str, stream: Any = None) -> str:
    """Wrap ``text`` in ANSI style codes, unless color is disabled."""
    text = str(text)
    if not styles or not color_enabled(stream):
        return text
    prefix = ''.join(_ANSI[s] for s in styles if s in _ANSI)
    return f"{prefix}{text}{_ANSI['reset']}" if prefix else text


def configure_logging(debug: bool) -> logging.Logger:
    """Configure and return the colored module logger."""
    log_level = logging.DEBUG if debug else logging.INFO
    logger = colorlog.getLogger('intelx_scanner')
    logger.setLevel(log_level)
    # Avoid duplicate handlers if called more than once (e.g. tests).
    if not logger.handlers:
        handler = colorlog.StreamHandler()
        handler.setLevel(log_level)
        handler.setFormatter(
            colorlog.ColoredFormatter(
                '[%(log_color)s%(levelname)s%(reset)s] %(message)s',
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white',
                },
            )
        )
        logger.addHandler(handler)
    else:
        for handler in logger.handlers:
            handler.setLevel(log_level)
    return logger


def resolve_api_key(args: argparse.Namespace, log: logging.Logger) -> Optional[str]:
    """Resolve the IntelX API key from the CLI flag or the environment."""
    if args.apikey:
        return args.apikey
    load_dotenv()
    api_key = os.getenv('INTELX_API_KEY')
    if api_key:
        log.debug("Using API key from environment variable: [hidden]")
    return api_key


def resolve_output_path(args: argparse.Namespace) -> str:
    """Compute the main output file path inside the ``out/`` directory."""
    if not args.output:
        return f"out/{args.target}-creds.{args.format}"
    return f"out/{args.output}"


def compute_date_range(range_months: int, now: Optional[datetime] = None) -> Tuple[str, str]:
    """Return ``(date_from, date_to)`` strings spanning ``range_months`` back from now."""
    today = now or datetime.today()
    start = today - relativedelta(months=range_months)
    # Cover the whole final day; a 00:00:00 dateto would exclude anything leaked today.
    return start.strftime("%Y-%m-%d 00:00:00"), today.strftime("%Y-%m-%d 23:59:59")


# ── Safe-share output ────────────────────────────────────────────────────────
def resolve_safe_output_path(main_output_path: str, safe_output_arg: Optional[str]) -> str:
    """Resolve the destination path for the safe-share CSV output."""
    if safe_output_arg:
        if os.path.isabs(safe_output_arg) or safe_output_arg.startswith('out/'):
            return safe_output_arg
        return f"out/{safe_output_arg}"

    base_name = os.path.splitext(os.path.basename(main_output_path))[0]
    return os.path.join('out', f"{base_name}-safe.csv")


def iter_credentials_for_safe_share(main_output_path: str, output_format: str) -> Iterator[Dict[str, str]]:
    """Yield normalized credential dicts from the main output file."""
    if output_format == 'json':
        with open(main_output_path, 'r') as f:
            entries = json.load(f)

        if isinstance(entries, list):
            for entry in entries:
                yield {
                    'url': entry.get('url', ''),
                    'identity': entry.get('identity') or entry.get('email', ''),
                    'password': entry.get('password', ''),
                    'source': entry.get('source', ''),
                    'date': entry.get('date', ''),
                }

    elif output_format == 'csv':
        with open(main_output_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield {
                    'url': row.get('url', ''),
                    'identity': row.get('identity') or row.get('email', ''),
                    'password': row.get('password', ''),
                    'source': row.get('source', ''),
                    'date': row.get('date', ''),
                }

    else:  # txt
        with open(main_output_path, 'r') as f:
            for line in f:
                # Lines are "<date> | <canonical>"; split the date prefix back off.
                date = ''
                body = line
                if ' | ' in line:
                    prefix, _, body = line.partition(' | ')
                    prefix = prefix.strip()
                    date = '' if prefix == 'unknown' else prefix
                for target, user, password in parse_line_candidates(body):
                    yield {
                        'url': target,
                        'identity': user,
                        'password': password,
                        'source': '',
                        'date': date,
                    }


def write_safe_share_file(main_output_path: str, output_format: str, safe_output_path: str) -> int:
    """Create a sanitized CSV suitable for external sharing. Returns rows written."""
    safe_rows: List[Dict[str, str]] = []
    seen: Set[str] = set()

    for cred in iter_credentials_for_safe_share(main_output_path, output_format):
        identity = (cred.get('identity') or '').strip()
        password = (cred.get('password') or '').strip()
        if not identity or not password:
            continue

        dedup_key = f"{identity.lower()}:{password}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        safe_rows.append({
            'TARGET': cred.get('url', ''),
            'User': identity,
            'Password': anonymize_password(password),
            'Date': cred.get('date', ''),
            'Source': cred.get('source', ''),
        })

    if not safe_rows:
        return 0

    safe_dir = os.path.dirname(safe_output_path)
    if safe_dir:
        os.makedirs(safe_dir, exist_ok=True)

    with open(safe_output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['TARGET', 'User', 'Password', 'Date', 'Source'], delimiter=';')
        writer.writeheader()
        writer.writerows(safe_rows)

    return len(safe_rows)


# ── IntelX search ────────────────────────────────────────────────────────────
def run_search(
    ix: Any,
    search_terms: Iterable[str],
    buckets: Iterable[str],
    date_from: str,
    date_to: str,
    max_results: int,
    log: logging.Logger,
) -> List[Dict[str, Any]]:
    """Search every (term, bucket) pair and return storageid-deduplicated records."""
    all_results: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    for term in search_terms:
        for bucket in buckets:
            log.debug(f"Searching bucket '{bucket}' for '{term}'...")
            try:
                try:
                    response = ix.search(
                        term,
                        maxresults=max_results,
                        buckets=[bucket],
                        datefrom=date_from,
                        dateto=date_to,
                    )
                except TypeError as e:
                    # intelxapi can raise this when the API returns {'records': None}.
                    if "'NoneType' object is not iterable" in str(e):
                        log.debug(
                            f"IntelX SDK returned null records for term '{term}' in bucket '{bucket}', "
                            "treating as empty result"
                        )
                        response = {'records': []}
                    else:
                        raise

                records = response.get('records') if isinstance(response, dict) else []
                if not records:
                    records = []
                for r in records:
                    sid = r.get('storageid')
                    if sid and sid not in seen_ids:
                        seen_ids.add(sid)
                        all_results.append(r)
                log.debug(f"  -> {len(records)} records from {bucket} for '{term}'")
            except EXPECTED_LEAK_ERRORS as e:
                log.warning(f"Bucket '{bucket}' failed for '{term}': {e}")
                continue

    log.info(f"Found {len(all_results)} unique results across all buckets")
    return all_results


def _extract_buckets_from_capabilities(caps: Any) -> List[str]:
    """Best-effort pull of accessible bucket ids from a GET_CAPABILITIES payload.

    The ``/authenticate/info`` response shape varies by account tier and SDK
    version, so we probe the known location and accept only non-empty strings
    (or ``{bucket|name|id}`` objects). Returns ``[]`` when none are found, which
    signals the caller to fall back to the curated default list.
    """
    if not isinstance(caps, dict):
        return []
    raw = caps.get('buckets')
    if not isinstance(raw, list):
        return []

    ordered: List[str] = []
    seen: Set[str] = set()
    for item in raw:
        name = None
        if isinstance(item, str):
            name = item.strip()
        elif isinstance(item, dict):
            candidate = item.get('bucket') or item.get('name') or item.get('id')
            if isinstance(candidate, str):
                name = candidate.strip()
        if name and name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def resolve_buckets(ix: Any, log: logging.Logger) -> Tuple[str, ...]:
    """Return the buckets to search.

    Prefers the account's actually-licensed buckets (so freshly-added sources
    such as stealer logs are covered without editing the code); falls back to
    the curated ``BUCKETS`` default whenever capabilities can't be determined.
    """
    try:
        caps = ix.GET_CAPABILITIES()
    except Exception as e:  # noqa: BLE001 - a best-effort probe must never abort the run
        log.debug(f"GET_CAPABILITIES failed ({e}); using default bucket list")
        return BUCKETS

    buckets = _extract_buckets_from_capabilities(caps)
    if buckets:
        log.info(f"Using {len(buckets)} licensed buckets from account capabilities")
        log.debug(f"Licensed buckets: {buckets}")
        return tuple(buckets)

    log.debug("Could not determine licensed buckets from capabilities; using default list")
    return BUCKETS


# ── Multi-file archive expansion ─────────────────────────────────────────────
# Many leaks (stealer logs, combolist bundles) are archives/folders. FILE_VIEW on
# the container's storage id returns an index, not the credential text, so we walk
# the treeview and fetch each child file instead.
_ARCHIVE_EXTS: Tuple[str, ...] = (
    '.zip', '.rar', '.7z', '.tar', '.tar.gz', '.tgz', '.gz', '.bz2', '.xz',
)
_TREEVIEW_SID_RE = re.compile(r'storageid=([^&"\'\s<>]+)', re.IGNORECASE)
_TREEVIEW_BUCKET_RE = re.compile(r'bucket=([^&"\'\s<>]+)', re.IGNORECASE)
_TREEVIEW_TYPE_RE = re.compile(r'[?&]type=(\d+)', re.IGNORECASE)
_TREEVIEW_NAME_RE = re.compile(r'>([^<>]+)</a>')


def _looks_like_container(record: Dict[str, Any]) -> bool:
    """Heuristic: does this search record look like an archive/folder bundle?"""
    name = str(record.get('name') or '').strip().lower()
    return bool(name) and name.endswith(_ARCHIVE_EXTS)


def _parse_treeview_children(treeview_html: str, parent: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract child-file leak records from a FILE_TREE_VIEW HTML payload.

    Child storage ids / buckets live in the ``<a href>`` links; missing fields are
    inherited from ``parent`` so each child carries everything FILE_VIEW needs.
    """
    children: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for line in treeview_html.replace('&amp;', '&').split('\n'):
        if 'storageid=' not in line:
            continue
        sid_match = _TREEVIEW_SID_RE.search(line)
        if not sid_match:
            continue
        sid = sid_match.group(1)
        if not sid or sid == parent.get('storageid') or sid in seen:
            continue
        seen.add(sid)

        bucket_match = _TREEVIEW_BUCKET_RE.search(line)
        type_match = _TREEVIEW_TYPE_RE.search(line)
        name_match = _TREEVIEW_NAME_RE.search(line)
        children.append({
            'storageid': sid,
            'bucket': bucket_match.group(1) if bucket_match else parent.get('bucket', ''),
            'type': int(type_match.group(1)) if type_match else parent.get('type', 0),
            'media': parent.get('media', 0),
            'name': name_match.group(1).strip() if name_match else f"{parent.get('name', 'archive')}/{sid}",
        })
    return children


def expand_container_leaks(ix: Any, results: List[Dict[str, Any]], log: logging.Logger) -> List[Dict[str, Any]]:
    """Return ``results`` with the child files of any archive/folder records appended.

    The original records are always preserved; any treeview failure is swallowed so
    expansion can never lose a result or abort the run.
    """
    expanded: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    for record in results:
        expanded.append(record)
        sid = record.get('storageid')
        if sid:
            seen_ids.add(sid)
        if not _looks_like_container(record):
            continue

        try:
            treeview = ix.FILE_TREE_VIEW(record.get('storageid'))
        except EXPECTED_LEAK_ERRORS as e:
            log.debug(f"FILE_TREE_VIEW failed for '{record.get('name')}': {e}")
            continue
        if not isinstance(treeview, str) or not treeview.strip():
            continue

        added = 0
        for child in _parse_treeview_children(treeview, record):
            child_sid = child.get('storageid')
            if child_sid and child_sid not in seen_ids:
                seen_ids.add(child_sid)
                expanded.append(child)
                added += 1
        if added:
            log.info(f"Expanded container '{record.get('name')}' into {added} child file(s)")
    return expanded


# ── Phonebook (selector) discovery ───────────────────────────────────────────
# The IntelX Phonebook returns the *selectors* (emails, domains, URLs) tied to a
# term — a direct enumeration of leaked identities under a domain. The SDK's
# phonebooksearch() convenience calls sys.exit() on error, so we poll the raw
# endpoints ourselves and fail soft.
_PHONEBOOK_MAX_PAGES: int = 50


def _selector_value(selector: Any) -> str:
    if isinstance(selector, dict):
        value = selector.get('selectorvalue') or selector.get('value') or ''
        return value.strip() if isinstance(value, str) else ''
    if isinstance(selector, str):
        return selector.strip()
    return ''


def run_phonebook_search(
    ix: Any,
    term: str,
    buckets: Iterable[str],
    date_from: str,
    date_to: str,
    max_results: int,
    log: logging.Logger,
    poll_delay: float = 0.0,
) -> List[str]:
    """Enumerate selector values for ``term`` across ``buckets``, deduplicated."""
    selectors: List[str] = []
    seen: Set[str] = set()

    for bucket in buckets:
        try:
            search_id = ix.PHONEBOOK_SEARCH(
                term, maxresults=max_results, buckets=[bucket], datefrom=date_from, dateto=date_to,
            )
        except EXPECTED_LEAK_ERRORS as e:
            log.warning(f"Phonebook search failed for '{term}' in '{bucket}': {e}")
            continue

        # The SDK returns a long search-id string on success, or a short error code.
        if not isinstance(search_id, str) or len(search_id) <= 3:
            log.debug(f"Phonebook search not started for '{bucket}' (response: {search_id!r})")
            continue

        remaining = max_results
        for _ in range(_PHONEBOOK_MAX_PAGES):
            try:
                page = ix.PHONEBOOK_SEARCH_RESULT(search_id, limit=max(remaining, 1))
            except EXPECTED_LEAK_ERRORS as e:
                log.debug(f"Phonebook result fetch failed for '{bucket}': {e}")
                break
            if not isinstance(page, dict):
                break

            page_selectors = page.get('selectors') or []
            for selector in page_selectors:
                value = _selector_value(selector)
                key = value.lower()
                if value and key not in seen:
                    seen.add(key)
                    selectors.append(value)

            remaining -= len(page_selectors)
            status = page.get('status')
            # 1 = no more results, 2 = search id not found; 0/3 = keep polling.
            if status in (1, 2) or remaining <= 0:
                break
            if poll_delay:
                time.sleep(poll_delay)

    log.info(f"Phonebook discovery found {len(selectors)} unique selector(s)")
    return selectors


def write_phonebook_output(selectors: Iterable[str], output_path: str, log: logging.Logger) -> int:
    """Write discovered selectors (one per line) to ``output_path``; returns the count."""
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    written = 0
    with open(output_path, 'w') as f:
        for selector in selectors:
            f.write(f"{selector}\n")
            written += 1
    log.info(f"Wrote {written} discovered selector(s) to: {output_path}")
    return written


# ── Resume: load previously saved credentials ───────────────────────────────
def load_existing_dedup(output_file: str, output_format: str, log: logging.Logger) -> Set[str]:
    """Load dedup keys from an existing output file so resumed runs skip them.

    Failure to parse the existing file is non-fatal: it returns whatever was
    loaded so far (possibly empty). The on-write dedup pass is the safety net.
    """
    seen: Set[str] = set()
    if not os.path.exists(output_file):
        return seen

    log.info(f"Resuming: loading existing credentials from {output_file}")
    try:
        if output_format == 'json':
            with open(output_file, 'r') as f:
                existing = json.load(f)
            for entry in existing:
                identity = entry.get('identity') or entry.get('email', '')
                password = entry.get('password', '')
                if identity and password:
                    seen.add(f"{identity.lower()}:{password}")
        elif output_format == 'csv':
            with open(output_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    identity = row.get('identity') or row.get('email', '')
                    password = row.get('password', '')
                    if identity and password:
                        seen.add(f"{identity.lower()}:{password}")
        else:  # txt
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        candidates = extract_credentials_from_line(line, mode='aggressive')
                        if candidates:
                            for candidate in candidates:
                                seen.add(candidate['dedup_key'])
                        else:
                            seen.add(line.lower())
        log.info(f"Loaded {len(seen)} existing credentials for dedup")
    except (json.JSONDecodeError, ValueError, OSError) as e:
        log.warning(f"Could not parse existing output file ({e}); starting fresh dedup")
    return seen


# ── FILE_VIEW with retries ──────────────────────────────────────────────────
def file_view_with_retry(
    ix: Any,
    leak: Dict[str, Any],
    log: logging.Logger,
    retry: RetryConfig = RetryConfig(),
) -> str:
    """Call FILE_VIEW with exponential backoff retry. Re-raises after the last attempt."""
    delay = retry.retry_delay
    for attempt in range(1, retry.max_retries + 1):
        try:
            return ix.FILE_VIEW(leak['type'], leak['media'], leak['storageid'], leak['bucket'])
        except EXPECTED_LEAK_ERRORS as e:
            if attempt == retry.max_retries:
                raise
            log.warning(f"FILE_VIEW attempt {attempt}/{retry.max_retries} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)
            delay *= 2
    return ""


# ── Rate limiting & progress ─────────────────────────────────────────────────
class RateLimiter:
    """Enforce a minimum spacing between calls across threads."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        """Block until at least ``delay`` seconds have elapsed since the previous call."""
        if self.delay <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self.delay - (now - self._last)
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last = time.monotonic()


class ProgressReporter:
    """Lightweight progress reporting for the leak-processing loop.

    Uses tqdm when available; otherwise prints a carriage-return counter to a
    TTY, and stays silent (the per-leak logs suffice) when output isn't a TTY
    or DEBUG logging is on.
    """

    def __init__(self, total: int, enabled: bool) -> None:
        self.total = total
        self.count = 0
        self.found = 0
        self._lock = threading.Lock()
        self._bar = None
        self._tty = enabled and sys.stderr.isatty()
        if enabled and _tqdm is not None:
            self._bar = _tqdm(total=total, unit='leak', desc='Processing leaks')

    def update(self, found_delta: int = 0) -> None:
        """Advance the progress counter by one leak and ``found_delta`` credentials."""
        with self._lock:
            self.count += 1
            self.found += found_delta
            if self._bar is not None:
                self._bar.set_postfix(found=self.found, refresh=False)
                self._bar.update(1)
            elif self._tty:
                sys.stderr.write(
                    f"\rProcessing leak {self.count}/{self.total} ({self.found} new creds)"
                )
                sys.stderr.flush()

    def close(self) -> None:
        """Finalize the progress display."""
        if self._bar is not None:
            self._bar.close()
        elif self._tty:
            sys.stderr.write("\n")
            sys.stderr.flush()


# ── Process leaks ────────────────────────────────────────────────────────────
def _leak_date(leak: Dict[str, Any]) -> str:
    """Return the leak's disclosure date as ``YYYY-MM-DD`` (or ``'unknown'``).

    IntelX records carry ``date`` (the item's own date) and ``added`` (when it
    was indexed); we prefer the former and normalize ISO/space timestamps to
    just the day so the value is readable in the output.
    """
    raw = str(leak.get('date') or leak.get('added') or '').strip()
    if not raw:
        return 'unknown'
    return raw.replace('T', ' ')[:10]


def _new_stats() -> Dict[str, int]:
    """Return a zeroed extraction-stats dict."""
    return {
        'lines_scanned': 0,
        'candidates_extracted': 0,
        'pattern_skips': 0,
        'low_confidence_skips': 0,
        'target_skips': 0,
        'multi_candidate_lines': 0,
        'duplicates': 0,
        'new_credentials': 0,
    }


def _process_contents(
    contents: str,
    leak: Dict[str, Any],
    *,
    mode: str,
    target: str,
    target_context: Any,
    person_context: Any,
    seen: Set[str],
    new_creds: List[Dict[str, Any]],
    stats: Dict[str, int],
    log: logging.Logger,
    scorer: Optional[ConfidenceModel] = None,
) -> int:
    """Extract, filter and dedup credentials from one leak's contents.

    Mutates ``seen``, ``new_creds`` and ``stats`` in place. The caller is
    responsible for serializing access to those structures. Returns the number
    of credentials newly accepted from this leak.

    When ``scorer`` is supplied, each candidate's heuristic ``confidence`` is
    replaced by the model's probability before the threshold check, so the ML
    model drives acceptance without touching the extractor itself.
    """
    min_confidence = EXTRACTION_MODES[mode]['min_confidence']
    accepted_total = 0

    for line in contents.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue

        stats['lines_scanned'] += 1

        candidates = extract_credentials_from_line(line_stripped, mode=mode)
        if not candidates:
            stats['pattern_skips'] += 1
            log.debug(f"Skipped (no valid credential pattern): {line_stripped}")
            continue

        stats['candidates_extracted'] += len(candidates)
        accepted_for_line = 0

        for candidate in candidates:
            if scorer is not None:
                candidate['confidence'] = scorer.score(candidate, line_stripped)
            if candidate['confidence'] < min_confidence:
                stats['low_confidence_skips'] += 1
                log.debug(f"Skipped (low confidence {candidate['confidence']:.2f}): {candidate['canonical']}")
                continue

            if person_context:
                target_match = candidate_mentions_person_email(candidate, line_stripped, person_context)
            else:
                target_match = candidate_mentions_target(candidate, line_stripped, target_context)

            if not target_match:
                stats['target_skips'] += 1
                log.debug(f"Skipped (target mismatch): {candidate['canonical']}")
                continue

            cred_key = candidate['dedup_key']
            if cred_key in seen:
                stats['duplicates'] += 1
                log.debug(f"Duplicate skipped: {candidate['canonical']}")
                continue

            seen.add(cred_key)

            identity = candidate['identity']
            email_value = identity if '@' in identity else ''

            new_creds.append({
                'url': candidate['url'],
                'identity': identity,
                'email': email_value,
                'password': candidate['password'],
                'source': leak.get('name', 'unknown'),
                'date': _leak_date(leak),
                'raw_line': line_stripped,
                'raw': line_stripped,
                'canonical': candidate['canonical'],
                'confidence': candidate['confidence'],
                'pattern': candidate['pattern'],
            })
            stats['new_credentials'] += 1
            accepted_for_line += 1
            accepted_total += 1
            log.info(f"Found ({candidate['pattern']} {candidate['confidence']:.2f}): {candidate['canonical']}")

        if accepted_for_line > 1:
            stats['multi_candidate_lines'] += 1

    return accepted_total


def process_leaks(
    ix: Any,
    results: List[Dict[str, Any]],
    *,
    mode: str,
    target: str,
    target_context: Any,
    person_context: Any,
    seen: Set[str],
    log: logging.Logger,
    workers: int = DEFAULT_WORKERS,
    delay: float = REQUEST_DELAY,
    retry: RetryConfig = RetryConfig(),
    scorer: Optional[ConfidenceModel] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Fetch and process every leak, optionally with bounded concurrency.

    FILE_VIEW network calls run on up to ``workers`` threads (rate-limited by
    ``delay``); credential extraction, dedup and result accumulation are
    serialized under a lock so ``seen``/``new_creds``/``stats`` stay consistent
    and writes remain thread-safe. With ``workers == 1`` this is equivalent to
    the original strictly-sequential behavior.
    """
    new_creds: List[Dict[str, Any]] = []
    stats = _new_stats()
    total = len(results)
    limiter = RateLimiter(delay)
    lock = threading.Lock()
    progress = ProgressReporter(total, enabled=log.level > logging.DEBUG)

    def handle(index: int, leak: Dict[str, Any]) -> None:
        log.debug(f"Processing leak [{index + 1}/{total}]: {leak.get('name', 'unknown')}")
        limiter.wait()
        try:
            contents = file_view_with_retry(ix, leak, log, retry)
        except EXPECTED_LEAK_ERRORS as e:
            log.error(f"Error processing leak {leak.get('name', 'unknown')}: {e}")
            progress.update(0)
            return

        with lock:
            try:
                accepted = _process_contents(
                    contents,
                    leak,
                    mode=mode,
                    target=target,
                    target_context=target_context,
                    person_context=person_context,
                    seen=seen,
                    new_creds=new_creds,
                    stats=stats,
                    log=log,
                    scorer=scorer,
                )
            except EXPECTED_LEAK_ERRORS as e:
                log.error(f"Error processing leak {leak.get('name', 'unknown')}: {e}")
                accepted = 0
        progress.update(accepted)

    try:
        if workers <= 1:
            for i, leak in enumerate(results):
                handle(i, leak)
        else:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(handle, i, leak) for i, leak in enumerate(results)]
                for future in as_completed(futures):
                    # Surface genuinely unexpected errors instead of swallowing them.
                    future.result()
    finally:
        progress.close()

    return new_creds, stats


# ── Output writing ───────────────────────────────────────────────────────────
def _load_json_entries(output_file: str, log: logging.Logger) -> List[Dict[str, Any]]:
    """Load existing JSON entries, recovering gracefully from corruption."""
    if not os.path.exists(output_file):
        return []
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
    except (json.JSONDecodeError, ValueError, OSError) as e:
        backup = output_file + '.corrupt'
        try:
            os.replace(output_file, backup)
            log.warning(f"Existing JSON output was corrupt ({e}); backed up to {backup}")
        except OSError:
            log.warning(f"Existing JSON output was corrupt ({e}); could not back it up")
        return []
    if not isinstance(data, list):
        log.warning("Existing JSON output is not a list; ignoring it for merge")
        return []
    return data


def _atomic_write_json(output_file: str, entries: List[Dict[str, Any]]) -> None:
    """Write ``entries`` to a temp file in the same directory, then atomically rename."""
    directory = os.path.dirname(output_file) or '.'
    os.makedirs(directory, exist_ok=True)
    tmp_path = f"{output_file}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, 'w') as f:
            json.dump(entries, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, output_file)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def write_json_output(new_creds: List[Dict[str, Any]], output_file: str, log: logging.Logger) -> int:
    """Merge new credentials with any existing entries and write atomically."""
    existing = _load_json_entries(output_file, log)
    _atomic_write_json(output_file, existing + new_creds)
    return len(new_creds)


def _existing_csv_keys(output_file: str, log: logging.Logger) -> Set[str]:
    """Read dedup keys already present in a CSV output file (best effort)."""
    keys: Set[str] = set()
    if not (os.path.exists(output_file) and os.path.getsize(output_file) > 0):
        return keys
    try:
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                identity = row.get('identity') or row.get('email', '')
                password = row.get('password', '')
                if identity and password:
                    keys.add(f"{identity.lower()}:{password}")
    except (OSError, csv.Error) as e:
        log.warning(f"Could not re-read existing CSV for dedup ({e}); relying on in-memory set")
    return keys


CSV_FIELDNAMES = [
    'url',
    'identity',
    'email',
    'password',
    'date',
    'source',
    'confidence',
    'pattern',
    'canonical',
    'raw_line',
]


def write_csv_output(new_creds: List[Dict[str, Any]], output_file: str, log: logging.Logger) -> int:
    """Append new credentials to a CSV, deduping against what is already on disk.

    This second-pass dedup is resilient even if the in-memory ``seen`` set
    failed to load, so duplicates are never appended.
    """
    on_disk = _existing_csv_keys(output_file, log)
    file_exists = os.path.exists(output_file) and os.path.getsize(output_file) > 0

    rows: List[Dict[str, Any]] = []
    for cred in new_creds:
        identity = (cred.get('identity') or '')
        password = cred.get('password', '')
        key = f"{identity.lower()}:{password}"
        if key in on_disk:
            continue
        on_disk.add(key)
        rows.append(cred)

    if not rows and file_exists:
        return 0

    directory = os.path.dirname(output_file) or '.'
    os.makedirs(directory, exist_ok=True)
    with open(output_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        for cred in rows:
            writer.writerow({key: cred.get(key, '') for key in CSV_FIELDNAMES})
    return len(rows)


def write_txt_output(new_creds: List[Dict[str, Any]], output_file: str, log: logging.Logger) -> int:
    """Append canonical credential strings to a plain-text file."""
    directory = os.path.dirname(output_file) or '.'
    os.makedirs(directory, exist_ok=True)
    with open(output_file, 'a') as f:
        for cred in new_creds:
            # "<date> | <canonical>" — the leading ' | ' is a chunk boundary for the
            # extractor, so the line still re-parses cleanly on resume/safe-share.
            f.write(f"{cred.get('date') or 'unknown'} | {cred['canonical']}\n")
    return len(new_creds)


def write_output(
    new_creds: List[Dict[str, Any]],
    output_file: str,
    output_format: str,
    log: logging.Logger,
) -> int:
    """Dispatch to the format-specific writer. Returns the number of rows written."""
    if output_format == 'json':
        return write_json_output(new_creds, output_file, log)
    if output_format == 'csv':
        return write_csv_output(new_creds, output_file, log)
    return write_txt_output(new_creds, output_file, log)


# ── Entry point ──────────────────────────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = parse_args(argv)
    log = configure_logging(args.debug)

    output_file = resolve_output_path(args)

    api_key = resolve_api_key(args, log)
    if not api_key:
        log.error(
            "API key is required. Please provide it using -k or set INTELX_API_KEY in your environment variables."
        )
        return 1

    intelx_client = load_intelx_client()
    if intelx_client is None:
        log.error("IntelX SDK not installed. Install dependencies with: pip install -r requirements.txt")
        return 1

    date_from, date_to = compute_date_range(args.range)
    log.info(f"Searching from {date_from} to {date_to}")

    target = args.target
    target_is_email = is_email_target(target)
    target_context = build_target_context(target)
    person_context = (
        build_person_email_context(target, person_name=args.person_name) if target_is_email else None
    )

    if args.person_name and not target_is_email:
        log.warning("--person-name is most useful with an email target and will be ignored for domain targets")

    search_terms = build_search_terms(
        target,
        include_email_pattern=args.email,
        person_name=args.person_name,
        company_wide=args.company_wide,
    )
    if target_is_email:
        log.info(f"Person-email mode enabled. Generated {len(search_terms)} search terms for '{target}'.")
    else:
        log.info(f"Domain mode: searching selector(s) {search_terms}")
        if args.company_wide:
            log.info("Company-wide search enabled: also sweeping the bare domain")

    try:
        ix = intelx_client(api_key)
        log.debug(f"IntelX API initialized for target: {target}")
        buckets = resolve_buckets(ix, log)
        results = run_search(ix, search_terms, buckets, date_from, date_to, args.maxresults, log)
        if args.expand_archives:
            results = expand_container_leaks(ix, results, log)
    except EXPECTED_LEAK_ERRORS as e:
        log.error(f"Error searching IntelX API: {e}")
        return 1

    os.makedirs('out', exist_ok=True)

    if args.phonebook:
        try:
            discovered: List[str] = []
            discovered_seen: Set[str] = set()
            for term in search_terms:
                for value in run_phonebook_search(
                    ix, term, buckets, date_from, date_to, args.maxresults, log, poll_delay=args.delay,
                ):
                    if value.lower() not in discovered_seen:
                        discovered_seen.add(value.lower())
                        discovered.append(value)
            emails_path = os.path.join('out', f"{args.target}-emails.txt")
            write_phonebook_output(discovered, emails_path, log)
        except EXPECTED_LEAK_ERRORS as e:
            log.error(f"Phonebook discovery failed: {e}")

    scorer: Optional[ConfidenceModel] = None
    if args.model:
        scorer = ConfidenceModel.load(args.model)
        if scorer is None:
            log.warning(
                f"Confidence model not usable at '{args.model}'; falling back to heuristic scoring. "
                "Train one with: python train_confidence_model.py"
            )
        else:
            log.info(f"Using ML confidence model from '{args.model}' (mode threshold acts as a probability cutoff)")

    seen = load_existing_dedup(output_file, args.format, log)

    new_creds, stats = process_leaks(
        ix,
        results,
        mode=args.mode,
        target=target,
        target_context=target_context,
        person_context=person_context,
        seen=seen,
        log=log,
        workers=args.workers,
        delay=args.delay,
        scorer=scorer,
    )

    written = 0
    try:
        if not new_creds:
            log.info(colorize("No new credentials found", 'yellow'))
        else:
            written = write_output(new_creds, output_file, args.format, log)
            log.info(
                f"Wrote {colorize(written, 'bold', 'green')} new credentials to: "
                f"{colorize(output_file, 'cyan')}"
            )
    except OSError as e:
        log.error(f"Cannot create/write to output file {output_file}: {e}")
        return 1

    if args.safe_share:
        try:
            safe_output_file = resolve_safe_output_path(output_file, args.safe_output)
            if os.path.exists(output_file):
                safe_count = write_safe_share_file(output_file, args.format, safe_output_file)
            else:
                safe_count = 0

            if safe_count > 0:
                log.info(f"Wrote {safe_count} anonymized credentials to safe-share file: {safe_output_file}")
            else:
                log.info("Safe-share skipped: 0 anonymized credentials")
        except (OSError, ValueError, json.JSONDecodeError, csv.Error) as e:
            log.error(f"Failed to create safe-share output: {e}")

    print_run_summary(target, written, len(seen), args.mode, stats)
    return 0


def print_run_summary(
    target: str,
    written: int,
    total_unique: int,
    mode: str,
    stats: Dict[str, Any],
) -> None:
    """Print a compact, color-coded end-of-run summary to stderr."""
    bar = colorize('─' * 52, 'dim')
    header = colorize(' credx — run summary ', 'bold', 'magenta')
    new_color = 'green' if written else 'yellow'

    def row(label: str, value: str) -> str:
        return f"  {colorize(label.ljust(24), 'bold')}  {value}"

    lines = [
        '',
        bar,
        header,
        bar,
        row('Target', colorize(target, 'cyan')),
        row('New this run', colorize(written, 'bold', new_color)),
        row('Total unique (all runs)', colorize(total_unique, 'bold', 'green')),
        bar,
        f"  {colorize('Extraction (' + mode + ')', 'dim')}",
        f"    scanned {colorize(stats['lines_scanned'], 'cyan')}  "
        f"candidates {colorize(stats['candidates_extracted'], 'cyan')}  "
        f"duplicates {colorize(stats['duplicates'], 'yellow')}",
        f"    skipped — pattern {colorize(stats['pattern_skips'], 'yellow')}  "
        f"low-conf {colorize(stats['low_confidence_skips'], 'yellow')}  "
        f"off-target {colorize(stats['target_skips'], 'yellow')}",
        bar,
        '',
    ]
    print('\n'.join(lines), file=sys.stderr)


if __name__ == '__main__':
    sys.exit(main())
