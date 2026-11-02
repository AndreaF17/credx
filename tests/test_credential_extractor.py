import unittest

from custom.credential_extractor import (
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
    is_email_target,
    looks_like_domain,
)


class DomainExactnessTests(unittest.TestCase):
    """A domain target matches only the exact domain by default; subdomains need
    --include-subdomains (include_subdomains=True)."""

    def _matches(self, target, line, include_subdomains=False):
        ctx = build_target_context(target, include_subdomains=include_subdomains)
        cands = extract_credentials_from_line(line, mode='balanced')
        return any(candidate_mentions_target(c, line, ctx) for c in cands)

    def test_exact_domain_matches(self):
        self.assertTrue(self._matches('example.com', 'example.com:admin:StrongPass1'))
        self.assertTrue(self._matches('example.com', 'user@example.com:StrongPass1'))
        self.assertTrue(self._matches('example.com', 'http://example.com/login:admin:StrongPass1'))

    def test_subdomain_excluded_by_default(self):
        self.assertFalse(self._matches('example.com', 'user@ds.example.com:StrongPass1'))
        self.assertFalse(self._matches('example.com', 'ds.example.com:admin:StrongPass1'))

    def test_lookalike_longer_domain_excluded(self):
        self.assertFalse(self._matches('example.com', 'user@example.com.evil.com:StrongPass1'))
        self.assertFalse(self._matches('example.com', 'user@notexample.com:StrongPass1'))

    def test_subdomain_included_with_flag(self):
        self.assertTrue(self._matches('example.com', 'user@ds.example.com:StrongPass1', include_subdomains=True))
        self.assertTrue(self._matches('example.com', 'user@deep.sub.example.com:StrongPass1', include_subdomains=True))
        # Exact still matches in subdomain mode.
        self.assertTrue(self._matches('example.com', 'user@example.com:StrongPass1', include_subdomains=True))

    def test_subdomain_mode_still_excludes_lookalike(self):
        self.assertFalse(self._matches('example.com', 'user@example.com.evil.com:StrongPass1', include_subdomains=True))


class CredentialExtractorTests(unittest.TestCase):
    def test_parses_scheme_less_host_format(self):
        line = 'stage.ivsanbernard.it/:stage.ivsanbernard.it:Nonmelaricordo1'
        candidates = extract_credentials_from_line(line, mode='balanced')

        self.assertTrue(candidates)
        best = candidates[0]
        self.assertEqual(best['identity'], 'stage.ivsanbernard.it')
        self.assertEqual(best['password'], 'Nonmelaricordo1')
        self.assertIn('stage.ivsanbernard.it', best['url'])

    def test_parses_kv_with_quoted_password(self):
        line = 'url=portal.example.com user=admin password="my secret pass"'
        candidates = extract_credentials_from_line(line, mode='balanced')

        self.assertTrue(candidates)
        kv = next((item for item in candidates if item['pattern'] == 'kv_pairs'), None)
        self.assertIsNotNone(kv)
        self.assertEqual(kv['password'], 'my secret pass')
        self.assertEqual(kv['identity'], 'admin')

    def test_extracts_multiple_credentials_in_one_line(self):
        line = 'site1.example.com:user1:Pass123! || site2.example.com:user2:Pass456!'
        candidates = extract_credentials_from_line(line, mode='balanced')
        canonicals = {item['canonical'] for item in candidates}

        self.assertGreaterEqual(len(canonicals), 2)

    def test_target_matching_with_obfuscation(self):
        line = 'hxxps://stage[.]ivsanbernard[.]it/login:admin:StrongPass1'
        candidates = extract_credentials_from_line(line, mode='balanced')
        target_context = build_target_context('stage.ivsanbernard.it')

        self.assertTrue(candidates)
        self.assertTrue(candidate_mentions_target(candidates[0], line, target_context))

    def test_target_matching_with_punycode(self):
        line = 'http://xn--mnich-kva.com/login:admin:StrongPass1'
        candidates = extract_credentials_from_line(line, mode='balanced')
        target_context = build_target_context('münich.com')

        self.assertTrue(candidates)
        self.assertTrue(candidate_mentions_target(candidates[0], line, target_context))

    def test_mode_difference_strict_vs_aggressive(self):
        line = 'stage.ivsanbernard.it ; admin ; abc123'

        strict_candidates = [
            item
            for item in extract_credentials_from_line(line, mode='strict')
            if item['confidence'] >= EXTRACTION_MODES['strict']['min_confidence']
        ]
        aggressive_candidates = [
            item
            for item in extract_credentials_from_line(line, mode='aggressive')
            if item['confidence'] >= EXTRACTION_MODES['aggressive']['min_confidence']
        ]

        self.assertEqual(strict_candidates, [])
        self.assertTrue(aggressive_candidates)

    def test_email_target_search_terms_include_person_variants(self):
        terms = build_search_terms(
            'john.doe@example.com',
            include_email_pattern=True,
            person_name='John Doe',
        )
        lowered_terms = {item.lower() for item in terms}

        self.assertIn('john.doe@example.com', lowered_terms)
        self.assertIn('@example.com', lowered_terms)
        self.assertIn('john doe', lowered_terms)
        # With an explicit person name, the dominant first.last corporate
        # username/email-local form is a desired search term.
        self.assertIn('john.doe', lowered_terms)
        self.assertIn('johndoe', lowered_terms)

    def test_email_target_default_uses_exact_email_only(self):
        terms = build_search_terms('info@example.it', include_email_pattern=False, person_name=None)
        self.assertEqual(terms, ['info@example.it'])

    def test_domain_target_defaults_to_email_selector(self):
        # Domain targets should query the @domain selector, not the bare company
        # name (which drags in ZoomInfo/CRM business-data documents).
        self.assertEqual(build_search_terms('recordati.it'), ['@recordati.it'])
        # A leading @ on the target must not double up.
        self.assertEqual(build_search_terms('@recordati.it'), ['@recordati.it'])

    def test_domain_target_company_wide_adds_bare_domain(self):
        terms = build_search_terms('recordati.it', company_wide=True)
        self.assertIn('@recordati.it', terms)
        self.assertIn('recordati.it', terms)

    def test_malformed_ipv6_url_in_kv_does_not_raise(self):
        line = 'url=http://[2001:db8::1 user=admin password=Pass123!'

        try:
            candidates = extract_credentials_from_line(line, mode='aggressive')
        except ValueError as exc:
            self.fail(f'extract_credentials_from_line raised ValueError: {exc}')

        self.assertTrue(candidates)
        self.assertTrue(any(item['url'].startswith('http://[2001') for item in candidates))

    def _accepted(self, line, mode='balanced'):
        """Candidates that clear the mode's confidence threshold (mirrors _process_contents)."""
        min_conf = EXTRACTION_MODES[mode]['min_confidence']
        return [
            item
            for item in extract_credentials_from_line(line, mode=mode)
            if item['confidence'] >= min_conf
        ]

    def test_rejects_date_triplets(self):
        # ZoomInfo / CRM exports produce colon/slash date rows that are not credentials.
        for line in ('7/26/2016:7/1/2016:1/17/2019', '6/9/2025:6/1/2025:6/11/2025'):
            self.assertEqual(self._accepted(line, mode='balanced'), [], line)
            self.assertEqual(self._accepted(line, mode='aggressive'), [], line)

    def test_rejects_numeric_and_money_triplets(self):
        for line in ('2292377000.00:USD:2682082026', '00.000:Investment Advisor:Milano'):
            self.assertEqual(self._accepted(line, mode='balanced'), [], line)
            self.assertEqual(self._accepted(line, mode='aggressive'), [], line)

    def test_rejects_crm_metadata_fields(self):
        lines = (
            'recordati.it:leadsourcecode@OData.Community.Display.V1.FormattedValue:Default Value',
            'microsoft.dynamics.crm.lookuplogicalname:systemuser:_modifiedby_value',
            'odata.community.display.v1.formattedvalue:Default Value:educationcode',
        )
        for line in lines:
            self.assertEqual(self._accepted(line, mode='balanced'), [], line)
            self.assertEqual(self._accepted(line, mode='aggressive'), [], line)

    def test_rejects_placeholder_passwords(self):
        for line in ('recordati.it:emailaddress2:null', 'app.corp.com:field:None'):
            self.assertEqual(self._accepted(line, mode='balanced'), [], line)

    def test_rejects_free_text_identities(self):
        # Identities with whitespace are business-data columns, not usernames.
        for line in ('recordati.it:Other Trade Show:Via Matteo', 'acme.com:Investment Advisor:Milano'):
            self.assertEqual(self._accepted(line, mode='balanced'), [], line)

    def test_rejects_dns_and_locator_chains(self):
        # WHOIS/DNS dumps: every token is a host or IP, so none is a password.
        lines = (
            'dns.technorail.com:dns2.technorail.com:dns3.arubadns.net',
            'dns3.arubadns.net:dns4.arubadns.cz:213.61.202.248',
            'host.com:camperiosim@camperio.net:camperio@legalmail.it',
        )
        for line in lines:
            self.assertEqual(self._accepted(line, mode='balanced'), [], line)
            self.assertEqual(self._accepted(line, mode='aggressive'), [], line)

    def test_keeps_host_as_identity_credential(self):
        # A hostname identity with a real password must still pass.
        line = 'stage.ivsanbernard.it/:stage.ivsanbernard.it:Nonmelaricordo1'
        self.assertTrue(self._accepted(line, mode='balanced'), line)

    def test_keeps_real_email_credentials(self):
        # Genuine combolist rows (as in the clean gamelife.it output) must survive.
        line = 'www.gamelife.it:revelth26@gmail.com:RainbowSixSiege12'
        accepted = self._accepted(line, mode='balanced')
        self.assertTrue(accepted)
        self.assertEqual(accepted[0]['identity'], 'revelth26@gmail.com')
        self.assertEqual(accepted[0]['password'], 'RainbowSixSiege12')

    def test_keeps_url_email_password(self):
        line = 'https://www.gamelife.it/customer/account/login/:attilio92@tiscali.it:Metallica92*'
        accepted = self._accepted(line, mode='balanced')
        self.assertTrue(accepted)
        self.assertEqual(accepted[0]['identity'], 'attilio92@tiscali.it')

    def test_person_email_matching_is_not_domain_only(self):
        context = build_person_email_context('john.doe@example.com')

        non_matching_candidate = {
            'identity': 'random.user@example.com',
            'url': 'example.com/login',
            'canonical': 'example.com/login:random.user@example.com:Pass123!',
        }
        matching_candidate = {
            'identity': 'john.doe@example.com',
            'url': 'example.com/login',
            'canonical': 'example.com/login:john.doe@example.com:Pass123!',
        }

        self.assertTrue(is_email_target('john.doe@example.com'))
        self.assertFalse(candidate_mentions_person_email(non_matching_candidate, non_matching_candidate['canonical'], context))
        self.assertTrue(candidate_mentions_person_email(matching_candidate, matching_candidate['canonical'], context))


class DomainDetectionTests(unittest.TestCase):
    def test_domains_detected(self):
        self.assertTrue(looks_like_domain('corp.com'))
        self.assertTrue(looks_like_domain('@corp.co.uk'))
        self.assertTrue(looks_like_domain('acme'))  # bare single token -> domain selector

    def test_names_are_not_domains(self):
        self.assertFalse(looks_like_domain('John Doe'))
        self.assertFalse(looks_like_domain('  jane  smith '))


class UsernameOptInTests(unittest.TestCase):
    def test_usernames_off_by_default(self):
        self.assertEqual(build_search_terms('john.doe@corp.com'), ['john.doe@corp.com'])

    def test_usernames_opt_in_adds_local_part_variants(self):
        terms = {t.lower() for t in build_search_terms('john.doe@corp.com', include_usernames=True)}
        self.assertIn('john.doe@corp.com', terms)
        self.assertIn('john.doe', terms)
        self.assertIn('john doe', terms)
        self.assertIn('johndoe', terms)


class PersonNameTargetTests(unittest.TestCase):
    def test_name_search_terms_without_domain(self):
        terms = build_name_search_terms('John Doe')
        self.assertIn('John Doe', terms)
        self.assertIn('johndoe', terms)
        self.assertNotIn('@corp.com', terms)

    def test_name_search_terms_with_domain_adds_selector(self):
        terms = build_name_search_terms('John Doe', domain='corp.com')
        self.assertIn('@corp.com', terms)

    def test_name_plus_domain_requires_both(self):
        ctx = build_person_name_context('John Doe', domain='corp.com')
        hit = {'identity': 'john.doe@corp.com', 'url': 'app.corp.com', 'canonical': 'app.corp.com:john.doe@corp.com:pw'}
        self.assertTrue(candidate_mentions_person_name(hit, 'john doe at corp.com', ctx))
        wrong_domain = {'identity': 'john doe', 'url': '', 'canonical': 'john doe:pw'}
        self.assertFalse(candidate_mentions_person_name(wrong_domain, 'john doe other.com', ctx))

    def test_name_only_matches_on_name_alone(self):
        ctx = build_person_name_context('John Doe')
        cand = {'identity': 'john doe', 'url': '', 'canonical': 'x'}
        self.assertTrue(candidate_mentions_person_name(cand, 'john doe:secret', ctx))

    def test_accented_name_matches_ascii_email(self):
        ctx = build_person_name_context('José García', domain='corp.com')
        cand = {'identity': 'jose.garcia@corp.com', 'url': '', 'canonical': 'jose.garcia@corp.com:pw'}
        self.assertTrue(candidate_mentions_person_name(cand, 'jose.garcia@corp.com:pw', ctx))

    def test_name_terms_include_first_last_form(self):
        terms = {t.lower() for t in build_name_search_terms('John Doe')}
        self.assertIn('john.doe', terms)
        self.assertIn('johndoe', terms)


class NormalizeAndRedosTests(unittest.TestCase):
    def test_fold_accents_matches_ascii(self):
        from custom.credential_extractor import normalize_for_matching
        self.assertEqual(normalize_for_matching('José García'), normalize_for_matching('Jose Garcia'))

    def test_email_inline_password_stops_at_colon(self):
        creds = extract_credentials_from_line('alice@corp.com:Secret123:2021-05-01')
        self.assertTrue(creds)
        self.assertEqual(creds[0]['password'], 'Secret123')

    def test_long_line_does_not_blow_up(self):
        import time
        line = 'ABCD/+' * 4000 + '.x'  # ~24KB, no trailing :password -> ReDoS trigger
        start = time.time()
        result = extract_credentials_from_line(line)
        self.assertIsInstance(result, list)
        self.assertLess(time.time() - start, 1.0)  # was multiple seconds before the guard

    def test_blob_over_max_len_returns_empty(self):
        self.assertEqual(extract_credentials_from_line('x' * 60000), [])


if __name__ == '__main__':
    unittest.main()
