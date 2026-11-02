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
import html as html_lib
import importlib
import io
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
    build_name_search_terms,
    build_person_email_context,
    build_person_name_context,
    build_search_terms,
    build_target_context,
    candidate_mentions_person_email,
    candidate_mentions_person_name,
    candidate_mentions_target,
    extract_credentials_from_line,
    has_dotted_tld,
    is_email_target,
    looks_like_domain,
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
# Default search range in months. Breached credentials are usually years old, so
# the default reaches back two years; narrow it with --range when you want recency.
DEFAULT_RANGE_MONTHS: int = 24
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


class AllSearchesFailed(Exception):
    """Raised when every (term, bucket) search failed — usually a systemic cause
    (invalid/expired API key, exhausted quota, rate limiting, or IntelX down),
    which must not be reported to the user as a clean 'no credentials' result."""


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
    parser.add_argument('-f', '--format', type=str, choices=['txt', 'json', 'csv', 'html'], help='Output format (txt, json, csv, html)', default='txt')
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
        '--phonebook-search', action='store_true',
        help='After enumerating selectors, also hunt credentials for each discovered '
             'email on the target domain (implies --phonebook). Big recall boost, but '
             'many extra API searches. Needs a domain anchor (email/domain target, or '
             '--domain for a person).',
    )
    parser.add_argument(
        '--phonebook-max', type=int, default=0,
        help='Cap how many discovered emails --phonebook-search hunts (0 = no cap, '
             'the default). Rate limiting still applies via --delay/--workers.',
    )
    parser.add_argument(
        '--person-name',
        type=str,
        default=None,
        help='Optional full name to enrich person-email search terms',
    )
    parser.add_argument(
        '--domain',
        type=str,
        default=None,
        help='Company domain to anchor a person-name target (e.g. --target "John Doe" '
             '--domain corp.com). Name matches are then required to co-occur with the '
             'domain, cutting noise.',
    )
    parser.add_argument(
        '--usernames', action='store_true',
        help='For an email target, also search username/local-part variants '
             '(john.doe -> "john doe", johndoe). Higher recall on username-indexed '
             'combolists, more noise. Off by default.',
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

    # --phonebook-search needs the enumeration step to feed it.
    if args.phonebook_search:
        args.phonebook = True

    if args.workers < 1:
        parser.error('--workers must be >= 1')
    if args.delay < 0:
        parser.error('--delay must be >= 0')
    if args.range < 1:
        parser.error('--range must be >= 1 (months)')
    if args.maxresults < 1:
        parser.error('--maxresults must be >= 1')
    if args.phonebook_max < 0:
        parser.error('--phonebook-max must be >= 0 (0 = no cap)')

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
        log.warning(
            "API key passed via --apikey is visible in your shell history and the process list; "
            "prefer INTELX_API_KEY in a .env file."
        )
        return args.apikey
    load_dotenv()
    api_key = os.getenv('INTELX_API_KEY')
    if api_key:
        log.debug("Using API key from environment variable: [hidden]")
    return api_key


def sanitize_filename(value: str, fallback: str = 'output') -> str:
    """Reduce a user/target-derived string to a safe bare filename.

    Strips any directory components and ``..`` so output can never escape the
    ``out/`` directory (e.g. a target of ``../../etc/x`` or ``a/b``).
    """
    name = os.path.basename(str(value).replace('\\', '/').strip())
    name = name.strip('. ')  # no leading dots / stray spaces, no bare ".."
    return name or fallback


def resolve_output_path(args: argparse.Namespace) -> str:
    """Compute the main output file path inside the ``out/`` directory."""
    if not args.output:
        target = sanitize_filename(args.target, fallback='target')
        return os.path.join('out', f"{target}-creds.{args.format}")
    return os.path.join('out', sanitize_filename(args.output))


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
        with open(main_output_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)

        if isinstance(entries, list):
            for entry in entries:
                yield {
                    'url': entry.get('url', ''),
                    'identity': entry.get('identity') or entry.get('email', ''),
                    'password': entry.get('password', ''),
                    'secret_type': entry.get('secret_type', 'plaintext'),
                    'source': entry.get('source', ''),
                    'date': entry.get('date', ''),
                }

    elif output_format == 'csv':
        with open(main_output_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                yield {
                    'url': row.get('url', ''),
                    'identity': row.get('identity') or row.get('email', ''),
                    'password': row.get('password', ''),
                    'secret_type': row.get('secret_type', 'plaintext'),
                    'source': row.get('source', ''),
                    'date': row.get('date', ''),
                }

    elif output_format == 'html':
        for entry in _load_html_records(main_output_path, logging.getLogger('intelx_scanner')):
            yield {
                'url': entry.get('url', ''),
                'identity': entry.get('identity') or entry.get('email', ''),
                'password': entry.get('password', ''),
                'secret_type': entry.get('secret_type', 'plaintext'),
                'source': entry.get('source', ''),
                'date': entry.get('date', ''),
            }

    else:  # txt
        with open(main_output_path, 'r', encoding='utf-8') as f:
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
                        'secret_type': 'plaintext',
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
            'TARGET': _csv_safe(cred.get('url', '')),
            'User': _csv_safe(identity),
            'Password': _csv_safe(anonymize_password(password)),
            'Type': _csv_safe(cred.get('secret_type', 'plaintext')),
            'Date': _csv_safe(cred.get('date', '')),
            'Source': _csv_safe(cred.get('source', '')),
        })

    if not safe_rows:
        return 0

    with _secure_open(safe_output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['TARGET', 'User', 'Password', 'Type', 'Date', 'Source'], delimiter=';')
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
    """Search every (term, bucket) pair and return storageid-deduplicated records.

    Raises :class:`AllSearchesFailed` if *every* search errored, so a systemic
    failure (bad key, quota, outage) is not mistaken for an empty result.
    """
    all_results: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()
    searches = 0
    failures = 0
    last_error: Optional[BaseException] = None

    for term in search_terms:
        for bucket in buckets:
            searches += 1
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
                if not isinstance(records, list):
                    records = []  # API returned a non-list (e.g. null) for records
                for r in records:
                    if not isinstance(r, dict):
                        continue  # skip malformed record entries
                    sid = r.get('storageid')
                    if sid and sid not in seen_ids:
                        seen_ids.add(sid)
                        all_results.append(r)
                log.debug(f"  -> {len(records)} records from {bucket} for '{term}'")
            except EXPECTED_LEAK_ERRORS as e:
                failures += 1
                last_error = e
                log.warning(f"Bucket '{bucket}' failed for '{term}': {e}")
                continue

    if searches and failures == searches:
        raise AllSearchesFailed(
            f"all {searches} IntelX search(es) failed (last error: {last_error}). "
            "Check your API key, remaining quota, and connectivity."
        )
    if failures:
        log.warning(f"{failures}/{searches} IntelX searches failed; results may be incomplete")

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
        empty_streak = 0
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
            # Guard against busy-polling empty, non-terminal pages forever.
            if not page_selectors:
                empty_streak += 1
                if empty_streak >= 3:
                    log.debug(f"Phonebook returned empty pages repeatedly for '{bucket}'; stopping")
                    break
            else:
                empty_streak = 0
            if poll_delay:
                time.sleep(poll_delay)
        else:
            log.warning(
                f"Phonebook hit the {_PHONEBOOK_MAX_PAGES}-page cap for '{bucket}'; "
                "results may be truncated (raise -m or narrow --range)."
            )

    log.info(f"Phonebook discovery found {len(selectors)} unique selector(s)")
    return selectors


def write_phonebook_output(selectors: Iterable[str], output_path: str, log: logging.Logger) -> int:
    """Write discovered selectors (one per line) to ``output_path``; returns the count."""
    written = 0
    with _secure_open(output_path, 'w') as f:
        for selector in selectors:
            f.write(f"{selector}\n")
            written += 1
    log.info(f"Wrote {written} discovered selector(s) to: {output_path}")
    return written


def resolve_phonebook_domain(
    target: str, domain_arg: Optional[str], is_person_name: bool = False
) -> Optional[str]:
    """Return the domain to anchor phonebook-discovered emails to, or None.

    ``--domain`` only anchors a person-name target (for email/domain targets the
    rest of the CLI ignores it and warns), so it is honored here only when
    ``is_person_name``. Otherwise the target's own domain is used: an email
    target's domain, or a domain target itself. A bare person-name target with no
    ``--domain`` yields None — there is nothing to scope the enumerated addresses
    to.
    """
    if is_person_name and domain_arg:
        return domain_arg.strip().lstrip('@').lower() or None
    target = (target or '').strip()
    if is_email_target(target):
        return target.rpartition('@')[2].lower() or None
    if looks_like_domain(target):
        return target.lstrip('@').lower() or None
    return None


def filter_emails_for_domain(selectors: Iterable[str], domain: str, cap: int = 0) -> List[str]:
    """Keep discovered selectors that are emails on ``domain`` (or a subdomain).

    Deduplicates case-insensitively while preserving first-seen order/casing, and
    caps the count when ``cap > 0`` (``0`` means no cap).
    """
    domain = (domain or '').strip().lstrip('@').lower()
    if not domain:
        return []
    suffix_exact = '@' + domain
    suffix_sub = '.' + domain
    out: List[str] = []
    seen: Set[str] = set()
    for selector in selectors:
        email = (selector or '').strip()
        lowered = email.lower()
        if '@' not in lowered:
            continue
        if not (lowered.endswith(suffix_exact) or lowered.endswith(suffix_sub)):
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        out.append(email)
        if cap and len(out) >= cap:
            break
    return out


def _merge_results(
    primary: List[Dict[str, Any]], extra: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Append ``extra`` leak records to ``primary``, deduplicating by storageid."""
    seen = {r.get('storageid') for r in primary if isinstance(r, dict)}
    for record in extra:
        if not isinstance(record, dict):
            continue
        sid = record.get('storageid')
        if sid not in seen:
            seen.add(sid)
            primary.append(record)
    return primary


def gather_phonebook_results(
    ix: Any,
    discovered: Iterable[str],
    domain: str,
    buckets: Iterable[str],
    date_from: str,
    date_to: str,
    max_results: int,
    cap: int,
    log: logging.Logger,
) -> List[Dict[str, Any]]:
    """Search each phonebook-discovered email on ``domain`` and return leak records.

    Returns an empty list (never raises) when there is nothing to search or every
    follow-up search fails, so a failed second pass never discards primary results.
    """
    emails = filter_emails_for_domain(discovered, domain, cap)
    if not emails:
        log.info(f"Phonebook-search: no discovered addresses on '{domain}' to hunt")
        return []
    log.info(f"Phonebook-search: hunting {len(emails)} discovered address(es) on '{domain}'")
    try:
        return run_search(ix, emails, buckets, date_from, date_to, max_results, log)
    except AllSearchesFailed as e:
        log.warning(
            f"Phonebook-search: every follow-up search failed ({e}); keeping primary results"
        )
        return []


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
            with open(output_file, 'r', encoding='utf-8') as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []  # a valid-JSON non-list is not our format; ignore it
            for entry in existing:
                if isinstance(entry, dict) and entry.get('password'):
                    seen.add(_dedup_key(entry))
        elif output_format == 'csv':
            with open(output_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get('password'):
                        seen.add(_dedup_key(row))
        elif output_format == 'html':
            for entry in _load_html_records(output_file, log):
                if isinstance(entry, dict) and entry.get('password'):
                    seen.add(_dedup_key(entry))
        else:  # txt
            with open(output_file, 'r', encoding='utf-8') as f:
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
    """Call FILE_VIEW with exponential backoff retry. Re-raises after the last attempt.

    The result is always coerced to ``str`` (``None`` -> ``''``, ``bytes`` decoded),
    so callers can split it safely regardless of what the SDK returns.
    """
    # Resolve the record's fields once: a missing field is a deterministic error,
    # so fail immediately instead of wasting the exponential-backoff retries on it.
    try:
        view_args = (leak['type'], leak['media'], leak['storageid'], leak['bucket'])
    except KeyError as e:
        raise KeyError(f"leak record missing required field {e}") from e

    delay = retry.retry_delay
    for attempt in range(1, retry.max_retries + 1):
        try:
            return _coerce_contents(ix.FILE_VIEW(*view_args))
        except EXPECTED_LEAK_ERRORS as e:
            if attempt == retry.max_retries:
                raise
            log.warning(f"FILE_VIEW attempt {attempt}/{retry.max_retries} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)
            delay *= 2
    return ""


def _coerce_contents(contents: Any) -> str:
    """Coerce a FILE_VIEW result to text: None -> '', bytes -> decoded str."""
    if contents is None:
        return ""
    if isinstance(contents, bytes):
        return contents.decode('utf-8', 'replace')
    return contents if isinstance(contents, str) else str(contents)


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
    target_context: Any,
    person_context: Any,
    seen: Set[str],
    new_creds: List[Dict[str, Any]],
    stats: Dict[str, int],
    log: logging.Logger,
    scorer: Optional[ConfidenceModel] = None,
    person_name_context: Any = None,
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

    # Iterate lines lazily (StringIO) rather than materializing a full list from
    # contents.split('\n'); large stealer-log dumps can be tens of MB.
    for line in io.StringIO(contents):
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
            elif person_name_context:
                target_match = candidate_mentions_person_name(candidate, line_stripped, person_name_context)
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
                'secret_type': candidate.get('secret_type', 'plaintext'),
                'source': leak.get('name', 'unknown'),
                'date': _leak_date(leak),
                'raw_line': line_stripped,
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
    target_context: Any,
    person_context: Any,
    seen: Set[str],
    log: logging.Logger,
    workers: int = DEFAULT_WORKERS,
    delay: float = REQUEST_DELAY,
    retry: RetryConfig = RetryConfig(),
    scorer: Optional[ConfidenceModel] = None,
    person_name_context: Any = None,
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
                    target_context=target_context,
                    person_context=person_context,
                    seen=seen,
                    new_creds=new_creds,
                    stats=stats,
                    log=log,
                    scorer=scorer,
                    person_name_context=person_name_context,
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
                try:
                    for future in as_completed(futures):
                        # Surface genuinely unexpected errors instead of swallowing them.
                        future.result()
                except KeyboardInterrupt:
                    for f in futures:
                        f.cancel()
                    raise
    except KeyboardInterrupt:
        # Keep whatever was collected so the caller can persist a resumable
        # partial file instead of discarding the whole (often long) run.
        log.warning(
            f"Interrupted — keeping {len(new_creds)} credential(s) collected so far; "
            "re-run the same command to resume."
        )
    finally:
        progress.close()

    return new_creds, stats


# ── Output writing ───────────────────────────────────────────────────────────
def _priv_opener(path: str, flags: int) -> int:
    """opener= for open(): create credential files with 0o600 (owner-only)."""
    return os.open(path, flags, 0o600)


def _secure_open(path: str, mode: str, **kwargs: Any):
    """open() for credential files: owner-only perms, UTF-8 text, hardened dir.

    Leaked credentials are sensitive; files are created 0o600 inside an 0o700
    ``out/`` directory, and a pre-existing file is tightened to 0o600 on append.
    """
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    pre_exists = os.path.exists(path)
    if 'b' not in mode:
        kwargs.setdefault('encoding', 'utf-8')
    handle = open(path, mode, opener=_priv_opener, **kwargs)
    if pre_exists:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return handle


# Cells beginning with these are interpreted as formulas by spreadsheet apps; a
# leading apostrophe neutralizes them (CSV injection defense).
_CSV_INJECTION_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def _csv_safe(value: Any) -> str:
    """Neutralize spreadsheet formula injection in a CSV cell."""
    text = '' if value is None else str(value)
    if text[:1] in _CSV_INJECTION_PREFIXES:
        return "'" + text
    return text


def _load_json_entries(output_file: str, log: logging.Logger) -> List[Dict[str, Any]]:
    """Load existing JSON entries, recovering gracefully from corruption."""
    if not os.path.exists(output_file):
        return []
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
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
        with _secure_open(tmp_path, 'w') as f:
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
        with open(output_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('password'):
                    keys.add(_dedup_key(row))
    except (OSError, csv.Error) as e:
        log.warning(f"Could not re-read existing CSV for dedup ({e}); relying on in-memory set")
    return keys


CSV_FIELDNAMES = [
    'url',
    'identity',
    'email',
    'password',
    'secret_type',
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
        key = _dedup_key(cred)
        if key in on_disk:
            continue
        on_disk.add(key)
        rows.append(cred)

    if not rows and file_exists:
        return 0

    with _secure_open(output_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        for cred in rows:
            writer.writerow({key: _csv_safe(cred.get(key, '')) for key in CSV_FIELDNAMES})
    return len(rows)


def write_txt_output(new_creds: List[Dict[str, Any]], output_file: str, log: logging.Logger) -> int:
    """Append canonical credential strings to a plain-text file."""
    with _secure_open(output_file, 'a') as f:
        for cred in new_creds:
            # "<date> | <canonical>" — the leading ' | ' is a chunk boundary for the
            # extractor, so the line still re-parses cleanly on resume/safe-share.
            f.write(f"{cred.get('date') or 'unknown'} | {cred['canonical']}\n")
    return len(new_creds)


# ── HTML report ───────────────────────────────────────────────────────────────
_HTML_DATA_RE = re.compile(
    r'<script id="credx-data" type="application/json">(.*?)</script>',
    re.DOTALL,
)

_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg: #f6f7f9; --panel: #ffffff; --text: #1a1d21; --muted: #6b7280;
    --border: #e5e7eb; --accent: #2563eb; --row: #fafbfc;
    --hi: #dc2626; --mid: #d97706; --lo: #16a34a;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0f1216; --panel: #171b21; --text: #e6e8eb; --muted: #9aa4b2;
      --border: #2a2f37; --accent: #60a5fa; --row: #1b2026;
      --hi: #f87171; --mid: #fbbf24; --lo: #4ade80;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  header {
    padding: 20px 16px; border-bottom: 1px solid var(--border); background: var(--panel);
  }
  h1 { margin: 0 0 4px; font-size: 20px; }
  .meta { color: var(--muted); font-size: 13px; }
  .controls {
    display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
    padding: 12px 16px; background: var(--panel); border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 2;
  }
  .controls input[type="search"] {
    flex: 1 1 220px; min-width: 160px; padding: 8px 10px; border-radius: 8px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text); font-size: 14px;
  }
  .controls label { display: inline-flex; gap: 6px; align-items: center; color: var(--muted); cursor: pointer; }
  .wrap { padding: 16px; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; min-width: 760px; background: var(--panel); border-radius: 10px; overflow: hidden; }
  th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); cursor: pointer; user-select: none; white-space: nowrap; }
  th:hover { color: var(--text); }
  tbody tr:nth-child(even) { background: var(--row); }
  td.pw { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; cursor: pointer; white-space: nowrap; }
  td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
  .pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .c-hi { color: var(--lo); } .c-mid { color: var(--mid); } .c-lo { color: var(--hi); }
  .empty { padding: 40px 16px; text-align: center; color: var(--muted); }
  footer { padding: 16px; color: var(--muted); font-size: 12px; text-align: center; }
  @media (max-width: 560px) { h1 { font-size: 18px; } }
</style>
</head>
<body>
<header>
  <h1>__TITLE__</h1>
  <div class="meta">Generated __GENERATED__ · <span id="count">__COUNT__</span> credential(s)</div>
</header>
<div class="controls">
  <input type="search" id="q" placeholder="Filter by any field (identity, url, source, password…)" autocomplete="off">
  <label><input type="checkbox" id="reveal"> Reveal passwords</label>
</div>
<div class="wrap">
  <table>
    <thead>
      <tr>
        <th data-k="date">Date</th>
        <th data-k="source">Source</th>
        <th data-k="url">URL</th>
        <th data-k="identity">Identity</th>
        <th data-k="password">Password</th>
        <th data-k="secret_type">Type</th>
        <th data-k="confidence">Conf.</th>
        <th data-k="pattern">Pattern</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
  <div class="empty" id="empty" hidden>No credentials match your filter.</div>
</div>
<footer>Generated by credx · passwords are masked by default — click a password or toggle "Reveal passwords"</footer>

<script id="credx-data" type="application/json">__DATA__</script>
<script>
(function () {
  "use strict";
  var raw = document.getElementById("credx-data").textContent || "[]";
  var data = [];
  try { data = JSON.parse(raw); } catch (e) { data = []; }
  var tbody = document.getElementById("rows");
  var empty = document.getElementById("empty");
  var q = document.getElementById("q");
  var reveal = document.getElementById("reveal");
  var sortKey = "confidence", sortDir = -1;

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function confClass(c) {
    c = Number(c) || 0;
    return c >= 0.85 ? "c-hi" : (c >= 0.66 ? "c-mid" : "c-lo");
  }
  function mask(p) { return "•".repeat(Math.max(6, Math.min(16, String(p || "").length))); }

  function render() {
    var term = (q.value || "").toLowerCase().trim();
    var showAll = reveal.checked;
    var rows = data.filter(function (r) {
      if (!term) return true;
      return [r.identity, r.email, r.url, r.password, r.secret_type, r.source, r.pattern, r.date]
        .some(function (v) { return String(v || "").toLowerCase().indexOf(term) !== -1; });
    });
    rows.sort(function (a, b) {
      var x = a[sortKey], y = b[sortKey];
      if (sortKey === "confidence") { x = Number(x) || 0; y = Number(y) || 0; }
      else { x = String(x || "").toLowerCase(); y = String(y || "").toLowerCase(); }
      return x < y ? -sortDir : (x > y ? sortDir : 0);
    });
    tbody.innerHTML = rows.map(function (r) {
      var pw = esc(r.password);
      var shown = showAll ? pw : esc(mask(r.password));
      var conf = (Number(r.confidence) || 0).toFixed(2);
      return "<tr>" +
        "<td>" + esc(r.date || "") + "</td>" +
        "<td>" + esc(r.source || "") + "</td>" +
        "<td class='mono'>" + esc(r.url || "") + "</td>" +
        "<td class='mono'>" + esc(r.identity || r.email || "") + "</td>" +
        "<td class='pw' data-pw='" + pw + "' title='click to toggle'>" + shown + "</td>" +
        "<td>" + esc(r.secret_type || "plaintext") + "</td>" +
        "<td><span class='pill " + confClass(r.confidence) + "'>" + conf + "</span></td>" +
        "<td>" + esc(r.pattern || "") + "</td>" +
        "</tr>";
    }).join("");
    empty.hidden = rows.length !== 0;
    document.getElementById("count").textContent = rows.length;
  }

  tbody.addEventListener("click", function (e) {
    var cell = e.target.closest ? e.target.closest("td.pw") : null;
    if (!cell) return;
    var real = cell.getAttribute("data-pw");
    var masked = cell.textContent.indexOf("•") !== -1;
    cell.textContent = masked ? (real || "") : real.replace(/./g, "•");
  });
  document.querySelectorAll("th[data-k]").forEach(function (th) {
    th.addEventListener("click", function () {
      var k = th.getAttribute("data-k");
      if (sortKey === k) { sortDir = -sortDir; } else { sortKey = k; sortDir = k === "confidence" ? -1 : 1; }
      render();
    });
  });
  q.addEventListener("input", render);
  reveal.addEventListener("change", render);
  render();
})();
</script>
</body>
</html>
"""


def _dedup_key(cred: Dict[str, Any]) -> str:
    identity = (cred.get('identity') or cred.get('email') or '')
    return f"{identity.lower()}:{cred.get('password', '')}"


def _load_html_records(output_file: str, log: logging.Logger) -> List[Dict[str, Any]]:
    """Parse the records embedded in a credx HTML report (for resume/accumulate)."""
    if not os.path.exists(output_file):
        return []
    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            match = _HTML_DATA_RE.search(f.read())
        if not match:
            return []
        # The embedded payload escapes <, >, & as \uXXXX; json.loads decodes them.
        data = json.loads(match.group(1))
        return data if isinstance(data, list) else []
    except (OSError, ValueError) as e:
        log.warning(f"Could not parse existing HTML report ({e}); starting fresh")
        return []


def _render_html_report(records: List[Dict[str, Any]]) -> str:
    """Render a self-contained, interactive HTML credential report."""
    generated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Escape every <, > and & as \uXXXX so the JSON can never break out of the
    # <script> data block (e.g. a leaked value containing "</script>" or "<!--").
    # JSON.parse (browser) and json.loads (resume) both decode these back.
    payload = (
        json.dumps(records, ensure_ascii=False)
        .replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('&', '\\u0026')
    )
    return (
        _HTML_TEMPLATE
        .replace('__TITLE__', html_lib.escape('credx — credential report'))
        .replace('__GENERATED__', html_lib.escape(generated))
        .replace('__COUNT__', str(len(records)))
        .replace('__DATA__', payload)
    )


def write_html_output(new_creds: List[Dict[str, Any]], output_file: str, log: logging.Logger) -> int:
    """Write an interactive HTML report, merging with any existing report.

    The report embeds its own records as JSON, so re-runs accumulate and dedup
    just like the JSON/CSV formats. Returns the number of newly added rows.
    """
    existing = _load_html_records(output_file, log)
    merged: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for cred in existing:
        key = _dedup_key(cred)
        if key not in seen:
            seen.add(key)
            merged.append(cred)

    added = 0
    for cred in new_creds:
        key = _dedup_key(cred)
        if key in seen:
            continue
        seen.add(key)
        merged.append(cred)
        added += 1

    tmp = f"{output_file}.tmp.{os.getpid()}"
    try:
        with _secure_open(tmp, 'w') as f:
            f.write(_render_html_report(merged))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, output_file)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return added


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
    if output_format == 'html':
        return write_html_output(new_creds, output_file, log)
    return write_txt_output(new_creds, output_file, log)


# ── Entry point ──────────────────────────────────────────────────────────────
def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = parse_args(argv)
    log = configure_logging(args.debug)

    output_file = resolve_output_path(args)
    if args.output:
        ext = os.path.splitext(output_file)[1].lstrip('.').lower()
        if ext and ext != args.format:
            log.warning(
                f"Output file extension '.{ext}' does not match --format {args.format}; "
                f"{args.format}-formatted content will be written to {output_file}."
            )

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
    # Person-name mode: a non-email, non-domain target (e.g. "John Doe"). A bare
    # single-token target (no dotted TLD) paired with --domain is also a person
    # name; a real domain (corp.com) stays in domain mode even with --domain.
    target_is_person_name = (not target_is_email) and (
        not looks_like_domain(target) or (bool(args.domain) and not has_dotted_tld(target))
    )

    target_context = build_target_context(target)
    person_context = (
        build_person_email_context(target, person_name=args.person_name) if target_is_email else None
    )
    person_name_context = (
        build_person_name_context(target, domain=args.domain) if target_is_person_name else None
    )

    # Flag-applicability feedback: warn when a flag has no effect for this target type.
    if args.person_name and not target_is_email:
        log.warning("--person-name only enriches an email target; ignoring it here")
    if args.domain and not target_is_person_name:
        log.warning("--domain only applies to a person-name target; ignoring it here")
    if args.email and not target_is_email:
        log.warning("--email only applies to an email target; ignoring it here")
    if args.usernames and not target_is_email:
        log.warning("--usernames only applies to an email target; ignoring it here")
    if args.company_wide and target_is_email:
        log.warning("--company-wide only applies to a domain target; ignoring it here")

    if target_is_person_name:
        search_terms = build_name_search_terms(target, domain=args.domain)
    else:
        search_terms = build_search_terms(
            target,
            include_email_pattern=args.email,
            person_name=args.person_name,
            company_wide=args.company_wide,
            include_usernames=args.usernames,
        )

    if not search_terms:
        log.error(f"Could not build any search terms for target '{target}'")
        return 1

    # Load the ML model (if any) BEFORE the rate-limited search, so a bad --model
    # path fails fast instead of after the whole run.
    scorer: Optional[ConfidenceModel] = None
    if args.model:
        scorer = ConfidenceModel.load(args.model)
        if scorer is None:
            log.warning(
                f"Confidence model not usable at '{args.model}'; falling back to heuristic scoring. "
                "Train one with: credx-train"
            )
        else:
            log.info(f"Using ML confidence model from '{args.model}' (mode threshold acts as a probability cutoff)")

    if target_is_person_name:
        if args.domain:
            log.info(
                f"Person-name mode: {len(search_terms)} term(s) for '{target}', "
                f"anchored to domain '{args.domain}'."
            )
        else:
            log.warning(
                f"Person-name mode without --domain: searching '{target}' broadly. "
                "Results will be noisy; pass --domain corp.com to anchor matches."
            )
    elif target_is_email:
        log.info(f"Person-email mode enabled. Generated {len(search_terms)} search terms for '{target}'.")
        if args.usernames:
            log.info("Username search enabled: also sweeping username/local-part variants")
    else:
        log.info(f"Domain mode: searching selector(s) {search_terms}")
        if args.company_wide:
            log.info("Company-wide search enabled: also sweeping the bare domain")

    try:
        ix = intelx_client(api_key)
        log.debug(f"IntelX API initialized for target: {target}")
        buckets = resolve_buckets(ix, log)
        results = run_search(ix, search_terms, buckets, date_from, date_to, args.maxresults, log)
    except AllSearchesFailed as e:
        log.error(str(e))
        return 2
    except EXPECTED_LEAK_ERRORS as e:
        log.error(f"Error searching IntelX API: {e}")
        return 1

    os.makedirs('out', exist_ok=True)

    discovered: List[str] = []
    if args.phonebook:
        try:
            discovered_seen: Set[str] = set()
            for term in search_terms:
                for value in run_phonebook_search(
                    ix, term, buckets, date_from, date_to, args.maxresults, log, poll_delay=args.delay,
                ):
                    if value.lower() not in discovered_seen:
                        discovered_seen.add(value.lower())
                        discovered.append(value)
            emails_path = os.path.join('out', f"{sanitize_filename(args.target, fallback='target')}-emails.txt")
            write_phonebook_output(discovered, emails_path, log)
        except EXPECTED_LEAK_ERRORS as e:
            log.error(f"Phonebook discovery failed: {e}")

    # Phonebook-search: feed domain-matching discovered emails back into the hunt.
    if args.phonebook_search:
        pb_domain = resolve_phonebook_domain(target, args.domain, is_person_name=target_is_person_name)
        if pb_domain:
            try:
                extra = gather_phonebook_results(
                    ix, discovered, pb_domain, buckets, date_from, date_to,
                    args.maxresults, args.phonebook_max, log,
                )
                before = len(results)
                _merge_results(results, extra)
                log.info(f"Phonebook-search added {len(results) - before} new leak(s) to process")
            except EXPECTED_LEAK_ERRORS as e:
                log.warning(f"Phonebook-search failed ({e}); keeping primary results")
        else:
            log.warning(
                "--phonebook-search needs a domain anchor (email/domain target, or "
                "--domain for a person); skipping the discovered-email hunt"
            )

    # Expand archives once, after phonebook-search, so discovered leaks are covered too.
    if args.expand_archives:
        try:
            results = expand_container_leaks(ix, results, log)
        except EXPECTED_LEAK_ERRORS as e:
            log.error(f"Archive expansion failed ({e}); continuing with unexpanded results")

    seen = load_existing_dedup(output_file, args.format, log)

    new_creds, stats = process_leaks(
        ix,
        results,
        mode=args.mode,
        target_context=target_context,
        person_context=person_context,
        person_name_context=person_name_context,
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
