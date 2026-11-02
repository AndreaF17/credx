"""Tests for hash-type detection, structured-dump parsing, and phonebook-search.

Covers the three post-review features:
  * #2 password-hash detection (secret_type tagging, end to end)
  * #3 structured-dump parsing (SQL INSERT, JSON/NDJSON, quoted CSV)
  * #1 phonebook-discovered-email search (domain filtering, cap, wiring)
"""
import json
import logging
import os
import tempfile
import unittest

import main
from custom.credential_extractor import (
    build_target_context,
    classify_secret,
    extract_credentials_from_line,
)


def _make_leak(storageid, name='leak', date=None):
    return {
        'storageid': storageid,
        'type': 0,
        'media': 0,
        'bucket': 'leaks.public',
        'name': name,
        'date': date or '2024-01-01T00:00:00',
    }


class _FakeIX:
    """Minimal IntelX stand-in: serves FILE_VIEW contents by storageid."""

    def __init__(self, contents_by_id=None):
        self.contents_by_id = contents_by_id or {}

    def FILE_VIEW(self, _type, _media, storageid, _bucket):
        return self.contents_by_id.get(storageid, '')


# ── #2 Hash detection ─────────────────────────────────────────────────────────
class ClassifySecretTests(unittest.TestCase):
    def test_md5_hex(self):
        self.assertEqual(classify_secret('5f4dcc3b5aa765d61d8327deb882cf99'), 'md5')

    def test_sha1_hex(self):
        self.assertEqual(classify_secret('da39a3ee5e6b4b0d3255bfef95601890afd80709'), 'sha1')

    def test_sha256_hex(self):
        self.assertEqual(classify_secret('a' * 64), 'sha256')

    def test_sha512_hex(self):
        self.assertEqual(classify_secret('b' * 128), 'sha512')

    def test_bcrypt(self):
        self.assertEqual(
            classify_secret('$2b$12$' + 'K' * 53), 'bcrypt'
        )

    def test_bcrypt_2a_variant(self):
        self.assertEqual(classify_secret('$2a$10$' + 'x' * 53), 'bcrypt')

    def test_md5crypt(self):
        self.assertEqual(classify_secret('$1$abcdefgh$' + 'x' * 22), 'md5crypt')

    def test_sha256crypt(self):
        self.assertEqual(classify_secret('$5$rounds=5000$abc$' + 'y' * 43), 'sha256crypt')

    def test_sha512crypt(self):
        self.assertEqual(classify_secret('$6$salt$' + 'z' * 86), 'sha512crypt')

    def test_argon2(self):
        self.assertEqual(
            classify_secret('$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaA'), 'argon2'
        )

    def test_phpass(self):
        self.assertEqual(classify_secret('$P$B' + 'a' * 30), 'phpass')

    def test_uppercase_hex_still_md5(self):
        self.assertEqual(classify_secret('5F4DCC3B5AA765D61D8327DEB882CF99'), 'md5')

    def test_plaintext_password(self):
        self.assertEqual(classify_secret('Summer2024!'), 'plaintext')

    def test_short_hex_is_not_a_hash(self):
        self.assertEqual(classify_secret('deadbeef'), 'plaintext')

    def test_empty_is_plaintext(self):
        self.assertEqual(classify_secret(''), 'plaintext')

    def test_hex_wrong_length_is_plaintext(self):
        # 33 hex chars matches no known digest length.
        self.assertEqual(classify_secret('a' * 33), 'plaintext')

    def test_non_hex_same_length_is_plaintext(self):
        # 32 chars but contains non-hex -> a real (strong) password, not a hash.
        self.assertEqual(classify_secret('Zz' + '0' * 30), 'plaintext')


class SecretTypeTaggingTests(unittest.TestCase):
    def test_candidate_tags_hashed_password(self):
        line = 'example.com:admin:5f4dcc3b5aa765d61d8327deb882cf99'
        best = extract_credentials_from_line(line, mode='balanced')[0]
        self.assertEqual(best['secret_type'], 'md5')

    def test_candidate_tags_plaintext_password(self):
        line = 'example.com:admin:Summer2024!'
        best = extract_credentials_from_line(line, mode='balanced')[0]
        self.assertEqual(best['secret_type'], 'plaintext')


class SecretTypeOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = logging.getLogger('test')
        self.log.addHandler(logging.NullHandler())
        self.cred = {
            'url': 'portal.example.com',
            'identity': 'admin@example.com',
            'email': 'admin@example.com',
            'password': '$2b$12$' + 'K' * 53,
            'secret_type': 'bcrypt',
            'source': 'dump.sql',
            'date': '2024-01-01',
            'confidence': 0.9,
            'pattern': 'host_delimited',
            'canonical': 'portal.example.com:admin@example.com:hash',
            'raw_line': 'x',
        }

    def test_csv_has_secret_type_column(self):
        self.assertIn('secret_type', main.CSV_FIELDNAMES)
        path = os.path.join(self.tmp.name, 'o.csv')
        main.write_csv_output([self.cred], path, self.log)
        with open(path, encoding='utf-8') as f:
            header = f.readline()
        self.assertIn('secret_type', header)

    def test_json_keeps_secret_type(self):
        path = os.path.join(self.tmp.name, 'o.json')
        main.write_json_output([self.cred], path, self.log)
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        self.assertEqual(data[0]['secret_type'], 'bcrypt')

    def test_html_has_type_column_and_payload(self):
        html = main._render_html_report([self.cred])
        self.assertIn('bcrypt', html)
        self.assertIn('>Type<', html)

    def test_safe_share_carries_type_column(self):
        src = os.path.join(self.tmp.name, 'creds.json')
        with open(src, 'w', encoding='utf-8') as f:
            json.dump([{
                'url': 'x.com', 'identity': 'admin', 'password': 'deadbeef' * 5,
                'secret_type': 'sha1', 'source': 'leakA',
            }], f)
        dest = os.path.join(self.tmp.name, 'safe.csv')
        main.write_safe_share_file(src, 'json', dest)
        import csv as _csv
        with open(dest, encoding='utf-8') as f:
            rows = list(_csv.DictReader(f, delimiter=';'))
        self.assertEqual(rows[0]['Type'], 'sha1')

    def test_process_leaks_sets_secret_type(self):
        ix = _FakeIX({'s1': 'example.com:admin:5f4dcc3b5aa765d61d8327deb882cf99'})
        new_creds, _ = main.process_leaks(
            ix,
            [_make_leak('s1')],
            mode='balanced',
            target_context=build_target_context('example.com'),
            person_context=None,
            seen=set(),
            log=self.log,
            workers=1,
            delay=0,
        )
        self.assertEqual(len(new_creds), 1)
        self.assertEqual(new_creds[0]['secret_type'], 'md5')


# ── #3 Structured-dump parsing ──────────────────────────────────────────────────
def _patterns(cands):
    return {c['pattern'] for c in cands}


class SqlInsertTests(unittest.TestCase):
    def test_basic_insert_email_password(self):
        line = "INSERT INTO users (id, email, password) VALUES (1, 'alice@corp.com', 'S3cretPass!');"
        cands = extract_credentials_from_line(line, mode='balanced')
        best = next(c for c in cands if c['pattern'] == 'sql_insert')
        self.assertEqual(best['identity'], 'alice@corp.com')
        self.assertEqual(best['password'], 'S3cretPass!')

    def test_multi_row_insert(self):
        line = "INSERT INTO u (email, pass) VALUES ('a@x.com','pass0001'),('b@x.com','pass0002');"
        cands = extract_credentials_from_line(line, mode='balanced')
        ids = {c['identity'] for c in cands if c['pattern'] == 'sql_insert'}
        self.assertEqual(ids, {'a@x.com', 'b@x.com'})

    def test_insert_hashed_password_tagged(self):
        line = "INSERT INTO u (email, password) VALUES ('u@x.com', '5f4dcc3b5aa765d61d8327deb882cf99');"
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'sql_insert')
        self.assertEqual(best['secret_type'], 'md5')

    def test_insert_backtick_columns(self):
        line = "INSERT INTO `users` (`email`, `password`) VALUES ('c@y.com', 'Passw0rd9');"
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'sql_insert')
        self.assertEqual(best['identity'], 'c@y.com')
        self.assertEqual(best['password'], 'Passw0rd9')

    def test_insert_with_escaped_quote_in_password(self):
        # SQL '' escape inside a quoted string.
        line = "INSERT INTO u (email, password) VALUES ('d@z.com', 'O''Brien12');"
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'sql_insert')
        self.assertEqual(best['password'], "O'Brien12")

    def test_insert_with_backslash_escaped_quote_in_password(self):
        # Backslash escape style inside a quoted string (the other escape branch).
        line = "INSERT INTO u (email, password) VALUES ('d@z.com', 'O\\'Brien12');"
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'sql_insert')
        self.assertEqual(best['password'], "O'Brien12")

    def test_insert_skips_null_password_uses_alternate_column(self):
        line = "INSERT INTO u (email, password, pwd) VALUES ('n@z.com', NULL, 'Fallback12');"
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'sql_insert')
        self.assertEqual(best['password'], 'Fallback12')


class FieldMappingTests(unittest.TestCase):
    """_pick_field must choose the right column: exact first, then guarded token
    match, never a short fragment hijacking an unrelated PII column."""

    def _one(self, line):
        cands = extract_credentials_from_line(line, mode='balanced')
        return cands[0] if cands else None

    def test_passport_is_not_treated_as_password(self):
        self.assertIsNone(self._one('{"email":"a@b.com","passport":"X1234567"}'))

    def test_avatar_hash_is_not_treated_as_password(self):
        self.assertIsNone(
            self._one('{"email":"x@corp.com","avatar_hash":"5f4dcc3b5aa765d61d8327deb882cf99"}')
        )

    def test_password_digest_is_found(self):
        best = self._one(
            '{"email":"x@corp.com","reset_password_token":"tok123xyz",'
            '"password_digest":"$2a$12$' + 'K' * 53 + '"}'
        )
        self.assertIsNotNone(best)
        self.assertEqual(best['secret_type'], 'bcrypt')

    def test_reset_token_is_not_the_password(self):
        # Only a reset-token column present: must not be emitted as a credential.
        self.assertIsNone(self._one('{"email":"x@corp.com","reset_password_token":"tok123xyz"}'))

    def test_numeric_user_id_not_chosen_over_username(self):
        best = self._one(
            '{"user_id":42,"username":"alice","url":"https://corp.com","password":"Secret123"}'
        )
        self.assertIsNotNone(best)
        self.assertEqual(best['identity'], 'alice')

    def test_email_verified_bool_not_chosen_as_identity(self):
        best = self._one(
            '{"emailVerified":true,"emailAddress":"alice@corp.com","password":"Secret123"}'
        )
        self.assertIsNotNone(best)
        self.assertEqual(best['identity'], 'alice@corp.com')

    def test_counter_column_not_chosen_as_identity(self):
        # 'login_count'/'login_ip' contain the 'login' token but are not identities.
        self.assertIsNone(
            self._one('{"login_count":7,"password":"Secret1!","url":"https://corp.com"}')
        )
        self.assertIsNone(
            self._one('{"login_ip":"10.0.0.1","password":"Secret1!","url":"https://corp.com"}')
        )

    def test_login_name_still_matched_as_identity(self):
        best = self._one('{"login_name":"alice","password":"Secret1!","url":"https://corp.com"}')
        self.assertIsNotNone(best)
        self.assertEqual(best['identity'], 'alice')

    def test_compound_pwd_and_pass_columns_found(self):
        for col in ('user_pwd', 'user_pass', 'member_password'):
            best = self._one('{"email":"a@b.com","%s":"Secret1!"}' % col)
            self.assertIsNotNone(best, f'{col} should be recognized as the password column')
            self.assertEqual(best['password'], 'Secret1!')

    def test_password_attempts_counter_not_chosen_as_password(self):
        best = self._one('{"email":"a@b.com","password_attempts":5,"user_pwd":"Secret1!"}')
        self.assertIsNotNone(best)
        self.assertEqual(best['password'], 'Secret1!')


class JsonObjectTests(unittest.TestCase):
    def test_json_email_password(self):
        line = '{"email": "dev@corp.com", "password": "Hunter2xx"}'
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'json_object')
        self.assertEqual(best['identity'], 'dev@corp.com')
        self.assertEqual(best['password'], 'Hunter2xx')

    def test_json_url_username_password(self):
        line = '{"url": "https://portal.corp.com", "username": "svcacct", "password": "RotateMe99"}'
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'json_object')
        self.assertEqual(best['identity'], 'svcacct')
        self.assertIn('portal.corp.com', best['url'])

    def test_json_hashed_password_tagged(self):
        line = '{"email":"x@y.com","password":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}'
        best = next(c for c in extract_credentials_from_line(line, mode='balanced')
                    if c['pattern'] == 'json_object')
        self.assertEqual(best['secret_type'], 'sha1')

    def test_json_without_credential_keys_ignored(self):
        line = '{"status":"ok","count":5}'
        self.assertEqual(extract_credentials_from_line(line, mode='balanced'), [])


class QuotedContactRowIsNotACredentialTests(unittest.TestCase):
    """Header-less quoted rows (contact/HR/CRM exports) must NOT become credentials:
    without a header, the field beside an email is as likely a name/role/id as a
    password, so these lines are left to the (precise) delimiter parsers, which
    correctly extract nothing from them."""

    def test_name_beside_email_is_not_a_password(self):
        for line in (
            '"alice@corp.com","Alice Smith","Str0ngPass!"',
            '"Jane Roe","Analyst","jane@corp.com","Finance"',
            '"alice@corp.com","Acme Corporation"',
            '"Smith","bob@corp.com"',
        ):
            cands = extract_credentials_from_line(line, mode='balanced')
            self.assertEqual(cands, [], f"expected no credential from contact row: {line!r}")


class StructuredPrecisionTests(unittest.TestCase):
    """A structured match is authoritative: the delimiter parsers must not also
    shred the same JSON/SQL line into junk candidates, and a JSON line the parser
    cannot map must not fall through to a mangled extraction."""

    def test_json_line_yields_only_the_structured_candidate(self):
        line = '{"email":"bob@corp.com","password":"R3alPassw0rd!"}'
        cands = extract_credentials_from_line(line, mode='balanced')
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]['pattern'], 'json_object')

    def test_json_with_null_password_falls_back_to_alternate_key(self):
        line = '{"email":"a@b.com","password":null,"pwd":"RealSecret1"}'
        cands = extract_credentials_from_line(line, mode='balanced')
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]['identity'], 'a@b.com')
        self.assertEqual(cands[0]['password'], 'RealSecret1')

    def test_json_null_password_no_alternate_yields_nothing(self):
        # Common SSO/federated shape: must not be shredded into a junk credential.
        line = '{"email":"a@b.com","password":null}'
        self.assertEqual(extract_credentials_from_line(line, mode='balanced'), [])

    def test_json_nested_value_is_not_shredded(self):
        line = '{"user":{"email":"a@x.com"},"password":"p1aaaa"}'
        cands = extract_credentials_from_line(line, mode='balanced')
        self.assertFalse(
            any('{' in c['identity'] or '}' in c['password'] for c in cands),
            f"nested JSON shredded into junk: {cands}",
        )

    def test_multi_row_sql_yields_only_structured_candidates(self):
        line = "INSERT INTO u (email, pass) VALUES ('a@x.com','pass0001'),('b@x.com','pass0002');"
        cands = extract_credentials_from_line(line, mode='balanced')
        self.assertEqual(len(cands), 2)
        self.assertTrue(all(c['pattern'] == 'sql_insert' for c in cands))


class StructuredRegressionTests(unittest.TestCase):
    def test_plain_combolist_line_unchanged(self):
        cands = extract_credentials_from_line('example.com:admin:StrongPass1', mode='balanced')
        self.assertEqual(cands[0]['pattern'], 'host_delimited')
        self.assertFalse({'sql_insert', 'json_object'} & _patterns(cands))

    def test_prose_mentioning_password_yields_nothing(self):
        cands = extract_credentials_from_line('Please reset your password at the portal soon', mode='balanced')
        self.assertEqual(cands, [])


# ── #1 Phonebook-discovered-email search ─────────────────────────────────────────
class _SearchIX:
    """Fake IntelX whose search() returns canned records per term and records calls."""

    def __init__(self, records_by_term):
        self.records_by_term = records_by_term
        self.terms = []

    def search(self, term, maxresults, buckets, datefrom, dateto):
        self.terms.append(term)
        return {'records': self.records_by_term.get(term, [])}


class ResolvePhonebookDomainTests(unittest.TestCase):
    def test_domain_from_email_target(self):
        self.assertEqual(main.resolve_phonebook_domain('john.doe@corp.com', None), 'corp.com')

    def test_domain_arg_wins_for_person(self):
        self.assertEqual(
            main.resolve_phonebook_domain('John Doe', 'Corp.com', is_person_name=True), 'corp.com'
        )

    def test_domain_from_domain_target(self):
        self.assertEqual(main.resolve_phonebook_domain('corp.com', None), 'corp.com')

    def test_none_for_person_without_domain(self):
        self.assertIsNone(main.resolve_phonebook_domain('John Doe', None, is_person_name=True))

    def test_stray_domain_ignored_for_domain_target(self):
        # --domain does not apply to a domain target (CLI warns + ignores it), so
        # the hunt must anchor to the target's own domain, not the stray --domain.
        self.assertEqual(
            main.resolve_phonebook_domain('example.com', 'corp.com', is_person_name=False),
            'example.com',
        )

    def test_stray_domain_ignored_for_email_target(self):
        self.assertEqual(
            main.resolve_phonebook_domain('a@example.com', 'corp.com', is_person_name=False),
            'example.com',
        )


class FilterEmailsForDomainTests(unittest.TestCase):
    def test_keeps_only_target_domain(self):
        sels = ['alice@corp.com', 'bob@other.com', 'not-an-email', 'eve@corp.com']
        self.assertEqual(
            main.filter_emails_for_domain(sels, 'corp.com'),
            ['alice@corp.com', 'eve@corp.com'],
        )

    def test_includes_subdomain(self):
        self.assertEqual(
            main.filter_emails_for_domain(['svc@mail.corp.com'], 'corp.com'),
            ['svc@mail.corp.com'],
        )

    def test_excludes_lookalike_domain(self):
        self.assertEqual(main.filter_emails_for_domain(['x@evilcorp.com'], 'corp.com'), [])

    def test_dedup_case_insensitive(self):
        self.assertEqual(
            main.filter_emails_for_domain(['A@corp.com', 'a@corp.com'], 'corp.com'),
            ['A@corp.com'],
        )

    def test_cap_limits_count(self):
        sels = [f'u{i}@corp.com' for i in range(5)]
        self.assertEqual(len(main.filter_emails_for_domain(sels, 'corp.com', cap=2)), 2)

    def test_zero_cap_is_unlimited(self):
        sels = [f'u{i}@corp.com' for i in range(5)]
        self.assertEqual(len(main.filter_emails_for_domain(sels, 'corp.com', cap=0)), 5)


class GatherPhonebookResultsTests(unittest.TestCase):
    def setUp(self):
        self.log = logging.getLogger('test')
        self.log.addHandler(logging.NullHandler())

    def test_hunts_only_domain_emails(self):
        ix = _SearchIX({
            'alice@corp.com': [{'storageid': 'A'}],
            'bob@corp.com': [{'storageid': 'B'}],
        })
        discovered = ['alice@corp.com', 'bob@corp.com', 'carol@other.com']
        results = main.gather_phonebook_results(
            ix, discovered, 'corp.com', ['leaks.public'], 'd1', 'd2', 100, 0, self.log,
        )
        self.assertEqual({r['storageid'] for r in results}, {'A', 'B'})
        self.assertNotIn('carol@other.com', ix.terms)

    def test_no_matching_emails_returns_empty(self):
        ix = _SearchIX({})
        results = main.gather_phonebook_results(
            ix, ['x@other.com'], 'corp.com', ['b'], 'd1', 'd2', 100, 0, self.log,
        )
        self.assertEqual(results, [])
        self.assertEqual(ix.terms, [])  # nothing to search


class MergeResultsTests(unittest.TestCase):
    def test_merges_and_dedups_by_storageid(self):
        primary = [{'storageid': 'A'}]
        extra = [{'storageid': 'A'}, {'storageid': 'C'}]
        merged = main._merge_results(primary, extra)
        self.assertEqual({r['storageid'] for r in merged}, {'A', 'C'})


class PhonebookSearchArgTests(unittest.TestCase):
    def test_phonebook_search_implies_phonebook(self):
        args = main.parse_args(['-t', 'corp.com', '--phonebook-search'])
        self.assertTrue(args.phonebook_search)
        self.assertTrue(args.phonebook)

    def test_phonebook_max_defaults_to_zero(self):
        args = main.parse_args(['-t', 'corp.com'])
        self.assertEqual(args.phonebook_max, 0)

    def test_negative_phonebook_max_rejected(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'corp.com', '--phonebook-max', '-1'])


if __name__ == '__main__':
    unittest.main()
