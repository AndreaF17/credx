#!/usr/bin/env python3
import csv
import io
import json
import re
import unicodedata
from urllib.parse import urlparse

# Inline credential regexes backtrack badly on very long lines with no trailing
# ``:password`` (minified JSON, base64 blobs, CRM rows IntelX returns). We cap the
# chunk length they scan so a pathological line can't stall a worker (ReDoS guard).
_MAX_INLINE_SCAN = 2000
# Absurdly long lines are blobs, not combolists; skip extraction entirely.
_MAX_LINE_LEN = 50000

DEFAULT_MODE = 'balanced'
EXTRACTION_MODES = {
    'strict': {
        'min_confidence': 0.82,
        'allow_kv': True,
        'enable_window_triplets': False,
        'allow_identity_without_url': False,
    },
    'balanced': {
        'min_confidence': 0.66,
        'allow_kv': True,
        'enable_window_triplets': True,
        'allow_identity_without_url': True,
    },
    'aggressive': {
        'min_confidence': 0.48,
        'allow_kv': True,
        'enable_window_triplets': True,
        'allow_identity_without_url': True,
    },
}

EMAIL_INLINE_PATTERN = re.compile(r'([^/:\s;|,]+@[^/:\s;|,]+\.[a-zA-Z]{2,}):([^:\s;|,]+)')
URL_INLINE_PATTERN = re.compile(r'((?:https?://)[^\s:;|,]+):([^:@/\s;|,]+):([^\s;|,]+)')
HOST_INLINE_PATTERN = re.compile(r'((?=[^:\s;|,]*[./])[^:\s;|,]+):([^:@/\s;|,]+):([^\s;|,]+)')
DELIMITER_PATTERN = re.compile(r'\s*[;|,\t]\s*')
KV_PAIR_PATTERN = re.compile(
    r'(?P<key>url|site|host|domain|user|username|login|email|pass|password|pwd)\s*[:=]\s*'
    r'(?P<value>"[^"]*"|\'[^\']*\'|.*?)(?=(?:\s+(?:url|site|host|domain|user|username|login|email|pass|password|pwd)\s*[:=])|$)',
    re.IGNORECASE,
)
EMAIL_TARGET_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
NAME_TOKEN_SPLIT_PATTERN = re.compile(r'[^a-z0-9]+')

# ── False-positive filters ───────────────────────────────────────────────────
# IntelX returns far more than combolists for a domain target: ZoomInfo / LinkedIn
# profiles and Dynamics-CRM / OData exports are tabular business data whose cells,
# split on ':', trivially matched the old loose host/triplet heuristics. The
# predicates below reject the three dominant noise shapes — dates/numbers, CRM
# metadata field names, and placeholder values — without touching real creds.

# Matches a hostname ending in a plausible alphabetic TLD (2-24 letters). Used to
# tell a real host (recordati.it) from numeric/date junk (2292377000.00, 7/1/2016).
_HOST_TLD_PATTERN = re.compile(r'\.[A-Za-z]{2,24}$')
# d/d/d or d-d-d style dates (7/26/2016, 2021-05-14) that show up as CRM cells.
_DATE_PATTERN = re.compile(r'^\d{1,4}[/.\-]\d{1,2}[/.\-]\d{1,4}$')
# Dotted-quad IPv4 address (213.61.202.248), common in DNS/WHOIS dumps.
_IPV4_PATTERN = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
# Values that are never a real identity or password.
_PLACEHOLDER_VALUES = frozenset({
    'null', 'none', 'nil', 'n/a', 'na', 'undefined', 'true', 'false', '-', '--',
})
# Substrings that mark a token as CRM/OData/export metadata rather than a credential.
_METADATA_SUBSTRINGS = (
    'odata.', '@odata', '.odata', 'microsoft.dynamics', 'dynamics.crm',
    'lookuplogicalname', 'formattedvalue', 'systemuser', '_value@', 'msdyn_',
    'msdip_', 'adx_', 'navigationproperty',
)


def _is_plausible_host(value):
    """True when ``value`` looks like a real host/URL, not a date, number or money figure."""
    value = sanitize_value(value)
    if not value:
        return False
    if '://' in value:
        return True
    host = value.split('/', 1)[0].split('?', 1)[0]
    if not re.search(r'[A-Za-z]', host):
        return False  # purely numeric/date (7/1/2016, 2292377000.00, 00.000)
    return bool(_HOST_TLD_PATTERN.search(host))


def _contains_metadata_token(*values):
    blob = ' '.join(value for value in values if value).lower()
    return any(token in blob for token in _METADATA_SUBSTRINGS)


def _is_placeholder(value):
    return sanitize_value(value).lower() in _PLACEHOLDER_VALUES


def _looks_like_locator(value):
    """True when ``value`` is a hostname/URL or IPv4 address (a network locator)."""
    value = sanitize_value(value)
    return _is_plausible_host(value) or bool(_IPV4_PATTERN.match(value))


# ── Password-hash detection ────────────────────────────────────────────────────
# Many dumps store hashed passwords, not plaintext. Tagging the hash type lets an
# operator pick the right cracking mode and tells a reader "this is a digest, not
# a usable password". Detection is conservative: a value is only called a hash when
# its shape is unambiguous (a known crypt prefix, or pure hex of an exact digest
# length), so strong random plaintext passwords are not mislabeled.

# Plain unsalted hex digests, keyed by hex length. 32 hex is reported as md5; NTLM
# shares that length and is indistinguishable from the value alone.
_HEX_HASH_BY_LEN = {
    32: 'md5', 40: 'sha1', 56: 'sha224', 64: 'sha256', 96: 'sha384', 128: 'sha512',
}
_HEX_ONLY_PATTERN = re.compile(r'^[0-9a-fA-F]+$')
# bcrypt: $2a$/$2b$/$2x$/$2y$, two-digit cost, then 53 chars of salt+digest.
_BCRYPT_PATTERN = re.compile(r'^\$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}$')
# Argon2 (i/d/id) and phpass/WordPress ($P$ / $H$) portable hashes.
_ARGON2_PATTERN = re.compile(r'^\$argon2(?:id|i|d)\$')
_PHPASS_PATTERN = re.compile(r'^\$[PH]\$[./A-Za-z0-9]{30,}$')
# Unix crypt() families identified by their numeric id prefix.
_CRYPT_PREFIXES = (
    ('$1$', 'md5crypt'),
    ('$5$', 'sha256crypt'),
    ('$6$', 'sha512crypt'),
)


def classify_secret(value):
    """Return the hash type of ``value`` (``md5``, ``bcrypt``, …) or ``plaintext``.

    Only unambiguous shapes are classified as hashes; anything else is treated as
    a plaintext password so real credentials are never hidden behind a wrong tag.
    """
    candidate = (value or '').strip()
    if not candidate:
        return 'plaintext'
    if _BCRYPT_PATTERN.match(candidate):
        return 'bcrypt'
    if _ARGON2_PATTERN.match(candidate):
        return 'argon2'
    if _PHPASS_PATTERN.match(candidate):
        return 'phpass'
    for prefix, name in _CRYPT_PREFIXES:
        if candidate.startswith(prefix):
            return name
    if len(candidate) in _HEX_HASH_BY_LEN and _HEX_ONLY_PATTERN.match(candidate):
        return _HEX_HASH_BY_LEN[len(candidate)]
    return 'plaintext'


def _add_unique(target_list, seen, value):
    value = value.strip()
    if not value:
        return
    lowered = value.lower()
    if lowered in seen:
        return
    seen.add(lowered)
    target_list.append(value)


def sanitize_value(value):
    value = value.strip().strip('"\'').strip()
    return value.rstrip(';|,')


def normalize_obfuscations(value):
    result = value
    result = re.sub(r'hxxps://', 'https://', result, flags=re.IGNORECASE)
    result = re.sub(r'hxxp://', 'http://', result, flags=re.IGNORECASE)
    result = result.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    result = result.replace('\\.', '.')
    result = re.sub(r'\s+dot\s+', '.', result, flags=re.IGNORECASE)
    return result


def fold_accents(value):
    """Fold accented characters to ASCII (José -> Jose, Müller -> Muller).

    Lets an accented person name match its ASCII email/username form. Already-ASCII
    values are unchanged. (NFKD does not fold ß -> ss; that is out of scope.)
    """
    decomposed = unicodedata.normalize('NFKD', value)
    return ''.join(ch for ch in decomposed if not unicodedata.combining(ch))


def decode_punycode_host(host):
    labels = []
    for label in host.split('.'):
        if not label:
            continue
        try:
            labels.append(label.encode('ascii').decode('idna'))
        except UnicodeError:
            labels.append(label)
    return '.'.join(labels)


def canonicalize_url_part(url_part):
    url_part = sanitize_value(normalize_obfuscations(url_part))
    if not url_part:
        return ''

    parse_target = url_part if '://' in url_part else f'http://{url_part}'
    try:
        parsed = urlparse(parse_target)
        host = parsed.hostname
    except ValueError:
        # Broken URL fragments (commonly malformed IPv6 hosts) should not abort extraction.
        return url_part

    if host:
        decoded_host = decode_punycode_host(host)
        path = parsed.path or ''
        if path == '/':
            path = ''
        if '://' in url_part:
            scheme = parsed.scheme or 'http'
            return f"{scheme}://{decoded_host}{path}"
        return f"{decoded_host}{path}"
    return url_part


def normalize_for_matching(value):
    value = fold_accents(normalize_obfuscations(value))
    value = value.lower()
    return re.sub(r'[^a-z0-9]', '', value)


def is_email_target(target):
    normalized = normalize_obfuscations(target.strip().lower())
    return bool(EMAIL_TARGET_PATTERN.match(normalized))


def _derive_person_name_variants(email, person_name=None, include_local_from_email=False):
    variants = []
    seen = set()

    email = normalize_obfuscations(email.strip().lower())
    local_part, _, _ = email.partition('@')
    local_tokens = [token for token in re.split(r'[._\-]+', local_part) if token]

    if include_local_from_email:
        if local_part:
            _add_unique(variants, seen, local_part)

        if len(local_tokens) >= 2:
            _add_unique(variants, seen, f"{local_tokens[0]} {local_tokens[-1]}")
            _add_unique(variants, seen, ''.join(local_tokens))

    if person_name:
        clean_name = ' '.join(person_name.strip().split())
        if clean_name:
            _add_unique(variants, seen, clean_name)
            _add_unique(variants, seen, f'"{clean_name}"')

            # Fold accents before tokenizing so "José García" yields jose/garcia
            # forms that match ASCII usernames/emails, not jos/garca.
            name_tokens = [
                token
                for token in NAME_TOKEN_SPLIT_PATTERN.split(fold_accents(clean_name).lower())
                if token
            ]
            if len(name_tokens) >= 2:
                _add_unique(variants, seen, ''.join(name_tokens))
                # first.last is the dominant corporate username/email-local form.
                _add_unique(variants, seen, f"{name_tokens[0]}.{name_tokens[-1]}")

    return variants


def has_dotted_tld(target):
    """True when ``target`` has a dotted alphabetic TLD (``corp.com``), as opposed
    to a bare single token (``acme``) or a person name."""
    value = normalize_obfuscations(target.strip()).lstrip('@')
    return bool(_HOST_TLD_PATTERN.search(value))


def looks_like_domain(target):
    """True when ``target`` looks like a domain (or @domain), not a person name.

    A domain has no whitespace and ends in a dotted, alphabetic TLD
    (``corp.com``, ``@corp.co.uk``). Bare single words without a dot are treated
    as domains too (the historical behavior), so only multi-word targets fall
    through to person-name mode.
    """
    value = normalize_obfuscations(target.strip()).lstrip('@')
    if not value or any(ch.isspace() for ch in value):
        return False
    if _HOST_TLD_PATTERN.search(value):
        return True
    # Single bare token with no dot: keep historical domain-selector behavior.
    return '.' not in value


def build_search_terms(
    target,
    include_email_pattern=False,
    person_name=None,
    company_wide=False,
    include_usernames=False,
):
    """Build IntelX search terms for domain/email/person targeting.

    Email target: the exact email first, plus optional person-name variants and
    (with ``include_email_pattern``) the ``@domain`` pattern. With
    ``include_usernames`` it also searches username/local-part variants derived
    from the address (``john.doe`` -> ``john doe``, ``johndoe``) — higher recall
    on username-indexed combolists, at the cost of more noise.

    Domain target: the ``@domain`` *email selector* by default. It matches leaked
    account rows (``alice@domain:password``) while skipping the company-mention
    documents — ZoomInfo/LinkedIn profiles, Dynamics-CRM/OData exports — that a
    bare-domain search drags in. ``company_wide`` additionally searches the bare
    domain to catch host-form creds (``domain:user:password``); the extractor's
    filters discard the extra business-data noise that sweep surfaces.
    """
    target_normalized = normalize_obfuscations(target.strip())
    terms = []
    seen = set()

    if is_email_target(target_normalized):
        _add_unique(terms, seen, target_normalized)
        email_value = target_normalized.lower()
        _, _, domain = email_value.partition('@')

        # Default behavior: exact email only. Person-name and username variants
        # broaden recall only when explicitly requested.
        if person_name or include_usernames:
            for variant in _derive_person_name_variants(
                email_value,
                person_name=person_name,
                include_local_from_email=include_usernames,
            ):
                _add_unique(terms, seen, variant)

        if include_email_pattern and domain:
            _add_unique(terms, seen, f"@{domain}")

        return terms

    # Domain target: email selector by default, bare domain only when asked.
    # Lowercased for consistency with every other search-term builder.
    domain_plain = target_normalized.lstrip('@').lower()
    _add_unique(terms, seen, f"@{domain_plain}")
    if company_wide:
        _add_unique(terms, seen, domain_plain)

    return terms


def build_name_search_terms(person_name, domain=None):
    """Build IntelX search terms for a person-name target.

    Searches full-name variants (``"John Doe"``, ``johndoe``). When ``domain``
    is given, it also searches the ``@domain`` selector so results can be
    anchored to the person's organization.
    """
    terms = []
    seen = set()
    for variant in _derive_person_name_variants('', person_name=person_name):
        _add_unique(terms, seen, variant)
    if domain:
        domain_plain = normalize_obfuscations(domain.strip()).lstrip('@').lower()
        if domain_plain:
            _add_unique(terms, seen, f"@{domain_plain}")
    return terms


def build_person_name_context(person_name, domain=None):
    """Build matching context for a person-name target.

    ``name_variants`` holds normalized name forms to look for. When ``domain`` is
    set, matches are anchored: a line must mention both a name variant and the
    domain. Without a domain, a name variant alone matches (noisier).
    """
    name_variants = _derive_person_name_variants('', person_name=person_name)
    normalized_variants = {
        normalize_for_matching(variant.strip('"'))
        for variant in name_variants
        if variant.strip('"')
    }
    domain_plain = (
        normalize_obfuscations(domain.strip()).lstrip('@').lower() if domain else ''
    )
    return {
        'name_variants': {v.strip('"').lower() for v in name_variants if v.strip('"')},
        'name_normalized': {v for v in normalized_variants if v},
        'domain': domain_plain,
        'domain_normalized': normalize_for_matching(domain_plain) if domain_plain else '',
    }


def candidate_mentions_person_name(candidate, raw_line, person_context):
    """Match a candidate against a person-name target.

    With a domain, requires a name variant AND the domain in the same context.
    Without a domain, a name variant alone is enough.
    """
    domain_norm = person_context.get('domain_normalized', '')

    for lowered, normalized in _candidate_text_forms(candidate, raw_line):
        name_hit = any(
            variant and variant in lowered
            for variant in person_context.get('name_variants', ())
        ) or any(
            variant and variant in normalized
            for variant in person_context.get('name_normalized', ())
        )
        if not name_hit:
            continue

        if not domain_norm:
            return True
        if domain_norm in normalized:
            return True

    return False


def build_target_context(target):
    target_plain = target.lstrip('@').strip().lower()
    variants = {target_plain, normalize_obfuscations(target_plain).lower()}

    parsed = urlparse(target_plain if '://' in target_plain else f'http://{target_plain}')
    if parsed.hostname:
        variants.add(parsed.hostname.lower())
        variants.add(decode_punycode_host(parsed.hostname.lower()))

    normalized_variants = {normalize_for_matching(item) for item in variants if item}
    normalized_variants = {item for item in normalized_variants if item}
    return {
        'target_plain': target_plain,
        'variants': {item for item in variants if item},
        'normalized_variants': normalized_variants,
    }


def build_person_email_context(email, person_name=None):
    """Build strict context for matching a specific person email target."""
    normalized_email = normalize_obfuscations(email.strip().lower())
    local_part, _, domain = normalized_email.partition('@')
    name_variants = _derive_person_name_variants(
        normalized_email,
        person_name=person_name,
        include_local_from_email=False,
    )

    return {
        'email': normalized_email,
        'email_normalized': normalize_for_matching(normalized_email),
        'local_part': local_part,
        'local_normalized': normalize_for_matching(local_part),
        'domain': domain,
        'domain_normalized': normalize_for_matching(domain),
        'name_variants': name_variants,
    }


def looks_like_url_part(value):
    # A credential anchor must resemble a real host/URL — a bare dot or slash
    # (dates, money figures, numeric IDs) is not enough.
    return _is_plausible_host(value)


def looks_like_identity(value):
    value = sanitize_value(value)
    if not value or ':' in value or '\n' in value:
        return False
    if any(ch.isspace() for ch in value):
        return False  # "Investment Advisor", "Default Value" are CRM columns, not users
    if _DATE_PATTERN.match(value) or _is_placeholder(value):
        return False
    return True


def looks_like_password(value, mode):
    value = sanitize_value(value)
    if not value:
        return False

    min_length = 3
    if mode == 'strict':
        min_length = 5
    return len(value) >= min_length


def calculate_confidence(identity, password, url_part, pattern):
    base = {
        'url_delimited': 0.94,
        'host_delimited': 0.88,
        'email_delimited': 0.86,
        # Structured dumps are explicitly keyed, so an extracted pair is high-signal.
        'sql_insert': 0.90,
        'json_object': 0.88,
        'csv_row': 0.86,
        'kv_pairs': 0.78,
        'window_triplet': 0.62,
    }.get(pattern, 0.55)

    if '@' in identity:
        base += 0.05
    if looks_like_url_part(url_part):
        base += 0.04
    if len(password) >= 8:
        base += 0.04
    if re.search(r'\d', password) and re.search(r'[A-Za-z]', password):
        base += 0.03

    base = min(base, 0.99)
    return round(base, 3)


def _candidate_text_forms(candidate, raw_line):
    """Yield ``(lowered, normalized)`` forms for every text tied to a candidate.

    Shared by all candidate_mentions_* matchers so they scan the same fields in
    the same order (raw line, identity, url, canonical).
    """
    for text in (
        raw_line,
        candidate.get('identity', ''),
        candidate.get('url', ''),
        candidate.get('canonical', ''),
    ):
        if text:
            yield normalize_obfuscations(text).lower(), normalize_for_matching(text)


def candidate_mentions_target(candidate, raw_line, target_context):
    for lowered, normalized in _candidate_text_forms(candidate, raw_line):
        for variant in target_context['variants']:
            if variant and variant in lowered:
                return True
        for normalized_variant in target_context['normalized_variants']:
            if normalized_variant and normalized_variant in normalized:
                return True
    return False


def candidate_mentions_person_email(candidate, raw_line, person_context):
    """Match candidate against a person email target without falling back to domain-only hits."""
    local_norm = person_context.get('local_normalized', '')
    domain_norm = person_context.get('domain_normalized', '')
    email_norm = person_context.get('email_normalized', '')

    for lowered, normalized in _candidate_text_forms(candidate, raw_line):
        # Strong match on the exact email (supports obfuscated variants via normalization)
        if email_norm and email_norm in normalized:
            return True

        # Fallback: local + domain co-occurrence in the same line/candidate context
        if local_norm and domain_norm and local_norm in normalized and domain_norm in normalized:
            if '@' in lowered or 'email' in lowered or 'user' in lowered or 'login' in lowered:
                return True

        # If a person name was supplied, require name + domain proximity in same text
        for name_variant in person_context.get('name_variants', []):
            if name_variant and name_variant.lower() in lowered and domain_norm and domain_norm in normalized:
                return True

    return False


def _mode_config(mode):
    return EXTRACTION_MODES.get(mode, EXTRACTION_MODES[DEFAULT_MODE])


def _build_candidate(candidates, seen, identity, password, url_part, pattern, raw_line, require_anchor=True):
    identity = sanitize_value(identity)
    password = sanitize_value(password)
    url_part = canonicalize_url_part(url_part)

    if not identity or not password:
        return

    # Reject CRM/OData export metadata regardless of which pattern matched it.
    if _contains_metadata_token(identity, url_part, password):
        return

    # The identity and password must be plausible credential values.
    identity_is_email = '@' in identity
    if not identity_is_email and not looks_like_identity(identity):
        return
    if _is_placeholder(password) or _DATE_PATTERN.match(password):
        return

    # DNS/WHOIS rows and contact dumps produce locator:locator:locator chains. A
    # real password is never a hostname/IP, so drop rows where both the identity
    # and the password are network locators (host-as-identity creds still pass,
    # because their password is not a locator).
    if _looks_like_locator(password) and (identity_is_email or _looks_like_locator(identity)):
        return

    # Require a trustworthy anchor: either a real host/URL or an email identity.
    # Without one, a candidate is almost always noise from tabular business data.
    # ``require_anchor=False`` is used only by the header-based CSV parser, where the
    # header already names the password column, so a bare username:password row is
    # a real credential rather than ambiguous tabular data.
    if not _is_plausible_host(url_part):
        url_part = ''
        if require_anchor and not identity_is_email:
            return

    dedup_key = f"{identity.lower()}:{password}"
    canonical = f"{url_part}:{identity}:{password}" if url_part else f"{identity}:{password}"

    if dedup_key in seen:
        return

    confidence = calculate_confidence(identity, password, url_part, pattern)
    seen.add(dedup_key)
    candidates.append({
        'identity': identity,
        'password': password,
        'url': url_part,
        'pattern': pattern,
        'confidence': confidence,
        'canonical': canonical,
        'dedup_key': dedup_key,
        'raw_line': raw_line,
        'secret_type': classify_secret(password),
    })


def _extract_from_kv_pairs(chunk, candidates, seen, mode):
    if not _mode_config(mode)['allow_kv']:
        return

    pairs = list(KV_PAIR_PATTERN.finditer(chunk))
    if not pairs:
        return

    current = {'url': '', 'identity': '', 'password': ''}
    for pair in pairs:
        key = pair.group('key').lower()
        value = sanitize_value(pair.group('value'))

        if key in {'url', 'site', 'host', 'domain'}:
            if current['identity'] and current['password']:
                _build_candidate(
                    candidates,
                    seen,
                    current['identity'],
                    current['password'],
                    current['url'],
                    'kv_pairs',
                    chunk,
                )
                current = {'url': '', 'identity': '', 'password': ''}
            current['url'] = value
        elif key in {'user', 'username', 'login', 'email'}:
            current['identity'] = value
        elif key in {'pass', 'password', 'pwd'}:
            current['password'] = value

        if current['identity'] and current['password']:
            _build_candidate(
                candidates,
                seen,
                current['identity'],
                current['password'],
                current['url'],
                'kv_pairs',
                chunk,
            )
            current = {'url': current['url'], 'identity': '', 'password': ''}


def _extract_from_triplet_windows(chunk, candidates, seen, mode):
    if not _mode_config(mode)['enable_window_triplets']:
        return

    normalized_chunk = DELIMITER_PATTERN.sub(':', chunk)
    tokens = [token.strip() for token in normalized_chunk.split(':') if token.strip()]
    for index in range(len(tokens) - 2):
        url_part, identity, password = tokens[index:index + 3]
        if not looks_like_url_part(url_part):
            continue
        if not looks_like_identity(identity):
            continue
        if not looks_like_password(password, mode):
            continue

        _build_candidate(candidates, seen, identity, password, url_part, 'window_triplet', chunk)


def _extract_from_inline_patterns(chunk, candidates, seen):
    # These patterns backtrack quadratically on a very long chunk that lacks the
    # trailing ":password"; cap the length they scan. KV/triplet passes still run.
    if len(chunk) > _MAX_INLINE_SCAN:
        return
    for match in URL_INLINE_PATTERN.finditer(chunk):
        _build_candidate(candidates, seen, match.group(2), match.group(3), match.group(1), 'url_delimited', chunk)

    for match in HOST_INLINE_PATTERN.finditer(chunk):
        _build_candidate(candidates, seen, match.group(2), match.group(3), match.group(1), 'host_delimited', chunk)

    for match in EMAIL_INLINE_PATTERN.finditer(chunk):
        prefix = chunk[:match.start()].rstrip(':').strip()
        _build_candidate(candidates, seen, match.group(1), match.group(2), prefix, 'email_delimited', chunk)


# ── Structured-dump parsing ─────────────────────────────────────────────────────
# Line-based delimiter parsing misses the structured formats breaches ship in: SQL
# dumps and JSON/NDJSON exports. These parsers run on the whole raw line (never the
# whitespace-split chunks, which would shatter a JSON object or a SQL value tuple)
# and route every pair through _build_candidate, so they inherit the same
# false-positive filters, confidence scoring, hash tagging and dedup. Both name the
# credential columns explicitly, so the password column is known — unlike a
# header-less CSV row, where "the field next to the email" is as likely to be a
# name, role or employee-id as a password, so that is deliberately not parsed here.

# Column / JSON-key name groups, in priority order (most specific first).
# `*_EXACT` keys match a whole column name; `*_TOKEN` keys also match when they are
# a word inside a compound name (password_hash, emailAddress). Token keys are kept
# long and unambiguous so short fragments can't hijack an unrelated column
# ('pass' must not match 'passport', 'hash' must not match 'avatar_hash').
_FIELD_IDENTITY_EXACT = (
    'email', 'e_mail', 'emailaddress', 'email_address', 'mail',
    'username', 'user_name', 'login', 'login_name', 'user', 'account', 'uid', 'userid',
)
_FIELD_IDENTITY_TOKEN = ('email', 'username', 'login')
_FIELD_PASSWORD_EXACT = (
    'password', 'passwd', 'password_hash', 'password_digest', 'passworddigest',
    'pass_hash', 'passhash', 'pwdhash', 'pwd_hash', 'pwd', 'pass', 'hash',
)
# 'pwd'/'pass' are safe as TOKEN keys (token matching is word-exact, so 'pass'
# matches a 'user_pass' column but never 'passport', which is a single token).
_FIELD_PASSWORD_TOKEN = ('password', 'passwd', 'pwd', 'pass')
_FIELD_URL_EXACT = ('url', 'uri', 'website', 'site', 'hostname', 'host', 'domain', 'origin')
_FIELD_URL_TOKEN = ('url', 'uri', 'website', 'hostname')
# Tokens that mark a compound column as *not* the live value even when it also
# carries a credential token: non-secret auth artifacts (reset_password_token,
# security_answer, email_verified) and metadata/counter/timestamp columns
# (login_count, password_attempts, password_changed_at, last_login).
_FIELD_SKIP_TOKENS = frozenset({
    'token', 'reset', 'salt', 'hint', 'question', 'answer', 'confirm',
    'verify', 'verified', 'recovery', 'otp',
    'count', 'attempts', 'attempt', 'failed', 'history', 'expiry', 'expires',
    'expiration', 'expired', 'created', 'updated', 'modified', 'changed',
    'date', 'time', 'at', 'last', 'first', 'status', 'flag', 'level',
    'number', 'num', 'total',
})
# Identity columns additionally reject network/metadata tokens that are never a
# username (login_ip, email_domain, account_id).
_IDENTITY_SKIP_TOKENS = _FIELD_SKIP_TOKENS | frozenset({'ip', 'domain', 'id'})
_CAMEL_BOUNDARY_RE = re.compile(r'(?<=[a-z0-9])(?=[A-Z])')

_SQL_INSERT_RE = re.compile(
    r'INSERT\s+INTO\s+\S+\s*\(([^)]*)\)\s*VALUES\s*(.+)',
    re.IGNORECASE | re.DOTALL,
)
# Stop after a sane number of value tuples so a pathological single-line dump
# (one giant multi-row INSERT) can't tie up a worker.
_SQL_MAX_TUPLES = 5000

# Per-field size cap for CSV parsing (10 MB): large enough for real blob columns,
# bounded against a pathological single field. Content is already in memory.
_CSV_FIELD_LIMIT = 10 * 1024 * 1024


def _field_tokens(name):
    """Split a column/key name into lowercase word tokens (snake_case + camelCase)."""
    snake = _CAMEL_BOUNDARY_RE.sub('_', name)
    return {token for token in re.split(r'[^A-Za-z0-9]+', snake.lower()) if token}


def _field_usable(value):
    """True when ``value`` is a real scalar worth using (not null/bool/placeholder/empty)."""
    if value is None or isinstance(value, (bool, dict, list)):
        return False
    text = str(value).strip()
    if not text:
        return False
    return text.lower() not in _PLACEHOLDER_VALUES


def _pick_field(pairs, exact_keys, token_keys, skip_tokens=_FIELD_SKIP_TOKENS):
    """Return the first usable value whose column/key matches ``keys``.

    Exact whole-name match takes priority (honoring key order); then a token match
    for the unambiguous ``token_keys``, skipping columns that carry a
    not-the-value marker token (``skip_tokens``). Null/empty/placeholder values are
    skipped so the search falls through to the next matching key (password=null ->
    pwd; login_count -> the real login column).
    """
    prepared = [(name.lower(), _field_tokens(name), value) for name, value in pairs]
    for key in exact_keys:
        for lname, _tokens, value in prepared:
            if lname == key and _field_usable(value):
                return value
    for key in token_keys:
        for _lname, tokens, value in prepared:
            if key in tokens and not (tokens & skip_tokens) and _field_usable(value):
                return value
    return ''


def _clean_sql_ident(col):
    """Normalize a SQL column name: drop quoting/backticks/brackets, lowercase."""
    return col.strip().strip('`"\'[]').strip().lower()


def _split_sql_tuples(blob):
    """Split a SQL ``VALUES`` blob into a list of field lists.

    Quote-aware (single/double), honoring ``''`` and ``\\'`` escapes, so commas and
    parens inside string literals do not split a field or end a tuple early.
    """
    tuples = []
    i, n = 0, len(blob)
    while i < n and len(tuples) < _SQL_MAX_TUPLES:
        if blob[i] != '(':
            i += 1
            continue
        fields, buf = [], []
        quoted = False
        in_quote = None
        closed = False
        j = i + 1
        while j < n:
            ch = blob[j]
            if in_quote is not None:
                if ch == '\\' and j + 1 < n:
                    buf.append(blob[j + 1])
                    j += 2
                    continue
                if ch == in_quote:
                    if j + 1 < n and blob[j + 1] == in_quote:  # '' -> literal quote
                        buf.append(in_quote)
                        j += 2
                        continue
                    in_quote = None
                    j += 1
                    continue
                buf.append(ch)
                j += 1
                continue
            if ch in ("'", '"'):
                in_quote = ch
                quoted = True
                j += 1
                continue
            if ch == ',':
                fields.append(''.join(buf) if quoted else ''.join(buf).strip())
                buf, quoted = [], False
                j += 1
                continue
            if ch == ')':
                fields.append(''.join(buf) if quoted else ''.join(buf).strip())
                closed = True
                j += 1
                break
            buf.append(ch)
            j += 1
        if closed and fields:
            tuples.append(fields)
            i = j
        else:
            break  # unbalanced parens: stop rather than rescan
    return tuples


def _extract_from_sql_insert(line, candidates, seen, mode):
    """Extract creds from a SQL INSERT. Returns True if the line IS such a statement
    (so the caller skips the delimiter parsers that would only shred it), even when
    no credential column was present."""
    match = _SQL_INSERT_RE.search(line)
    if not match:
        return False
    cols = [_clean_sql_ident(c) for c in match.group(1).split(',')]
    if not any(cols):
        return False  # INSERT ... VALUES without a usable column list: let legacy try
    for values in _split_sql_tuples(match.group(2)):
        pairs = list(zip(cols, values))
        identity = _pick_field(pairs, _FIELD_IDENTITY_EXACT, _FIELD_IDENTITY_TOKEN, _IDENTITY_SKIP_TOKENS)
        password = _pick_field(pairs, _FIELD_PASSWORD_EXACT, _FIELD_PASSWORD_TOKEN)
        url_part = _pick_field(pairs, _FIELD_URL_EXACT, _FIELD_URL_TOKEN)
        if identity and password:
            _build_candidate(candidates, seen, identity, password, url_part, 'sql_insert', line)
    return True


def _json_scalar(value):
    """Return a JSON value as a trimmed string, or '' for bools/null/containers."""
    if isinstance(value, bool):
        return ''
    if isinstance(value, (str, int, float)):
        return str(value).strip()
    return ''


def _extract_from_json_object(line, candidates, seen, mode):
    """Extract creds from a JSON object / array-of-objects line. Returns True if the
    line IS such JSON (so the caller skips the delimiter parsers that would only
    shred it), even when no credential key was present. A JSON array of plain
    strings is NOT treated as structured — it may be a combolist the delimiter
    parsers should handle."""
    stripped = line.strip()
    if not stripped or stripped[0] not in '{[':
        return False
    try:
        data = json.loads(stripped)
    except (ValueError, TypeError, RecursionError):
        # RecursionError: deeply-nested JSON in attacker-controlled leak content
        # (CPython's json raises it on Python <3.15); it is not a ValueError, so
        # it must be caught explicitly or it would abort the whole run.
        return False
    objects = data if isinstance(data, list) else [data]
    saw_object = False
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        saw_object = True
        pairs = [(str(k), v) for k, v in obj.items()]
        identity = _json_scalar(_pick_field(pairs, _FIELD_IDENTITY_EXACT, _FIELD_IDENTITY_TOKEN, _IDENTITY_SKIP_TOKENS))
        password = _json_scalar(_pick_field(pairs, _FIELD_PASSWORD_EXACT, _FIELD_PASSWORD_TOKEN))
        url_part = _json_scalar(_pick_field(pairs, _FIELD_URL_EXACT, _FIELD_URL_TOKEN))
        if identity and password:
            _build_candidate(candidates, seen, identity, password, url_part, 'json_object', line)
    return saw_object


def _looks_like_column_name(cell):
    """True when ``cell`` is a plausible CSV header label (short, no SQL/JSON
    punctuation, not a sentence) — so a SQL/JSON line split on commas is not
    mistaken for a header row."""
    cell = cell.strip()
    if not cell or len(cell) > 40:
        return False
    if any(ch in cell for ch in '()[]{}"\'=;:@/\\'):
        return False
    return len(cell.split()) <= 3


def _match_column_index(header, exact_keys, token_keys, skip_tokens):
    """Return the index of the first header column whose *name* matches ``keys``
    (exact, then guarded token), or None. Only columns that look like real header
    labels are considered."""
    prepared = [
        (str(name).strip().lower(), _field_tokens(str(name)), idx)
        for idx, name in enumerate(header)
        if _looks_like_column_name(str(name))
    ]
    for key in exact_keys:
        for lname, _tokens, idx in prepared:
            if lname == key:
                return idx
    for key in token_keys:
        for _lname, tokens, idx in prepared:
            if key in tokens and not (tokens & skip_tokens):
                return idx
    return None


def extract_credentials_from_csv(contents, mode=DEFAULT_MODE):
    """Parse a credential CSV whose header names the columns.

    Returns a list of candidate dicts, or ``None`` when the content is not a
    recognizable credential CSV (no header row naming BOTH an identity and a
    password column), so the caller can fall back to line-based parsing.

    Reliable because the header names the password column explicitly — unlike a
    header-less row, where the field beside an email is as likely a name or id as
    a password. Uses the csv module so quoted fields with embedded commas or
    newlines are handled correctly.
    """
    # Real breach CSVs often carry a large base64/blob/session column; raise the
    # per-field limit (default 128 KB) so one big field doesn't abort the parse and
    # silently drop every row after it.
    try:
        csv.field_size_limit(_CSV_FIELD_LIMIT)
    except (OverflowError, ValueError):
        pass

    reader = csv.reader(io.StringIO(contents))
    try:
        header = next(reader)
    except (StopIteration, csv.Error):
        return None
    if len(header) < 2:  # a real CSV header is a row of >= 2 column names
        return None

    identity_idx = _match_column_index(
        header, _FIELD_IDENTITY_EXACT, _FIELD_IDENTITY_TOKEN, _IDENTITY_SKIP_TOKENS
    )
    password_idx = _match_column_index(
        header, _FIELD_PASSWORD_EXACT, _FIELD_PASSWORD_TOKEN, _FIELD_SKIP_TOKENS
    )
    if identity_idx is None or password_idx is None:
        return None
    url_idx = _match_column_index(header, _FIELD_URL_EXACT, _FIELD_URL_TOKEN, _FIELD_SKIP_TOKENS)

    candidates = []
    seen = set()
    needed = max(identity_idx, password_idx)
    try:
        for row in reader:
            if len(row) <= needed:
                continue
            identity = row[identity_idx].strip()
            password = row[password_idx].strip()
            url_part = row[url_idx].strip() if (url_idx is not None and url_idx < len(row)) else ''
            if identity and password:
                # The header names the password column, so no URL/email anchor is required.
                _build_candidate(
                    candidates, seen, identity, password, url_part, 'csv_row', ','.join(row),
                    require_anchor=False,
                )
    except csv.Error:
        # A malformed tail (field beyond even the raised limit) ends parsing; keep
        # what was already extracted rather than discarding the whole file.
        pass
    # Return None (not []) when nothing parsed, so the caller falls back to the
    # per-line parsers — the header alone is not proof the body is really CSV.
    return candidates or None


def _split_chunks(line):
    chunks = [line]
    for splitter in [r'\s*\|\|\s*', r'\s+\|\s+', r'\s*&&\s*', r'\s{2,}']:
        expanded = []
        for chunk in chunks:
            expanded.extend(re.split(splitter, chunk))
        chunks = expanded

    unique = []
    seen = set()
    for chunk in chunks:
        chunk = chunk.strip()
        if chunk and chunk not in seen:
            seen.add(chunk)
            unique.append(chunk)
    return unique


def extract_credentials_from_line(line, mode=DEFAULT_MODE):
    raw_line = line.strip()
    if not raw_line or len(raw_line) > _MAX_LINE_LEN:
        return []

    normalized_line = normalize_obfuscations(raw_line)
    candidates = []
    seen = set()

    # Structured formats (keyed, so the password column is unambiguous) parse the
    # whole raw line first. A recognized SQL/JSON line is authoritative — the
    # delimiter parsers below would only shred its punctuation into noise — so they
    # are skipped whenever the line IS structured, even if it yielded no credential
    # (e.g. a JSON row whose password is null, or a non-credential table).
    structured = _extract_from_sql_insert(raw_line, candidates, seen, mode)
    structured = _extract_from_json_object(raw_line, candidates, seen, mode) or structured

    if not structured:
        chunks = _split_chunks(normalized_line)
        if raw_line not in chunks:
            chunks.append(raw_line)

        for chunk in chunks:
            _extract_from_inline_patterns(chunk, candidates, seen)
            _extract_from_kv_pairs(chunk, candidates, seen, mode)
            _extract_from_triplet_windows(chunk, candidates, seen, mode)

    mode_config = _mode_config(mode)
    if not mode_config['allow_identity_without_url']:
        candidates = [candidate for candidate in candidates if candidate.get('url')]

    return sorted(candidates, key=lambda item: item['confidence'], reverse=True)
