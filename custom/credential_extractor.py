#!/usr/bin/env python3
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


def _build_candidate(candidates, seen, identity, password, url_part, pattern, raw_line):
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
    if not _is_plausible_host(url_part):
        url_part = ''
        if not identity_is_email:
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
