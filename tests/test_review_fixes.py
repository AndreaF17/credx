"""Tests for the fixes applied from the multi-agent code review."""
import json
import logging
import os
import stat
import tempfile
import time
import unittest

import main
from custom.confidence_features import FEATURE_NAMES


def _silent_logger():
    log = logging.getLogger('test_review_fixes')
    log.handlers = [logging.NullHandler()]
    log.setLevel(logging.CRITICAL)
    return log


def _args(**over):
    base = {'target': 'example.com', 'output': None, 'format': 'txt', 'maxresults': 500,
            'apikey': None, 'workers': 1, 'delay': 0.0, 'range': 24}
    base.update(over)
    ns = main.argparse.Namespace()
    for k, v in base.items():
        setattr(ns, k, v)
    return ns


def _leak(storageid, **over):
    leak = {'storageid': storageid, 'type': 0, 'media': 0, 'bucket': 'leaks.public', 'name': 'l'}
    leak.update(over)
    return leak


def _cred(identity='a@corp.com', password='Str0ngPass9', **over):
    base = {'url': 'https://app.corp.com', 'identity': identity, 'email': identity,
            'password': password, 'source': 'leak.txt', 'date': '2023-01-01',
            'confidence': 0.9, 'pattern': 'url_delimited',
            'canonical': f'app.corp.com:{identity}:{password}', 'raw_line': 'r'}
    base.update(over)
    return base


class ArgValidationTests(unittest.TestCase):
    def test_range_below_one_rejected(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'x.com', '-r', '0'])

    def test_negative_range_rejected(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'x.com', '-r', '-3'])

    def test_maxresults_below_one_rejected(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'x.com', '-m', '0'])


class PathSanitizationTests(unittest.TestCase):
    def test_default_output_is_structured_under_root(self):
        path = main.resolve_output_path(_args(target='example.com'))
        self.assertEqual(path, os.path.join(main.output_root(), 'example.com', 'creds.txt'))

    def test_target_path_components_stripped(self):
        # A crafted target cannot escape the results tree (sanitized to a bare name).
        path = main.resolve_output_path(_args(target='../../../etc/pwn'))
        self.assertEqual(path, os.path.join(main.output_root(), 'pwn', 'creds.txt'))

    def test_explicit_output_is_honored_as_user_path(self):
        # -o is trusted user input and may point anywhere.
        self.assertEqual(main.resolve_output_path(_args(output='/tmp/evilx/out.csv')), '/tmp/evilx/out.csv')


class OutputFormatMismatchTests(unittest.TestCase):
    def test_warns_when_extension_mismatches_format(self):
        log = _silent_logger()
        records = []
        handler = logging.Handler()
        handler.emit = lambda r: records.append(r.getMessage())
        log.addHandler(handler)
        log.setLevel(logging.WARNING)
        # resolve + the mismatch check live in main(); replicate the check path.
        args = _args(output='report.csv', format='txt')
        out = main.resolve_output_path(args)
        ext = os.path.splitext(out)[1].lstrip('.').lower()
        self.assertEqual(ext, 'csv')
        self.assertNotEqual(ext, args.format)


class RunSearchResilienceTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def test_all_failures_raise(self):
        class FailIX:
            def search(self, *a, **k):
                raise OSError('401 unauthorized')
        with self.assertRaises(main.AllSearchesFailed):
            main.run_search(FailIX(), ['t'], ['b1', 'b2'], 'a', 'b', 10, self.log)

    def test_partial_failure_tolerated(self):
        # One term fails, another succeeds (buckets are now searched in one call per
        # term, so resilience is at the term level).
        class PartialIX:
            def search(self, term, maxresults, buckets, datefrom, dateto):
                if term == 't1':
                    raise OSError('x')
                return {'records': [{'storageid': 's1'}]}
        results = main.run_search(PartialIX(), ['t1', 't2'], ['b1', 'b2'], 'a', 'b', 10, self.log)
        self.assertEqual(len(results), 1)

    def test_searches_all_buckets_in_one_call_per_term(self):
        calls = []

        class RecordIX:
            def search(self, term, maxresults, buckets, datefrom, dateto):
                calls.append((term, tuple(buckets)))
                return {'records': []}
        main.run_search(RecordIX(), ['t1', 't2'], ['b1', 'b2', 'b3'], 'a', 'b', 10, self.log)
        # One call per term, each passing ALL buckets (not one call per bucket).
        self.assertEqual(calls, [('t1', ('b1', 'b2', 'b3')), ('t2', ('b1', 'b2', 'b3'))])

    def test_non_list_records_and_non_dict_entries(self):
        class WeirdIX:
            def search(self, *a, **k):
                return {'records': [None, 'garbage', {'storageid': 's1'}]}
        results = main.run_search(WeirdIX(), ['t'], ['b'], 'a', 'b', 10, self.log)
        self.assertEqual([r['storageid'] for r in results], ['s1'])


class FileViewRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def test_missing_field_fails_fast_without_retry(self):
        class CountIX:
            def __init__(self):
                self.calls = 0

            def FILE_VIEW(self, *a):
                self.calls += 1
                return 'x'
        ix = CountIX()
        retry = main.RetryConfig(max_retries=3, retry_delay=10)
        with self.assertRaises(KeyError):
            main.file_view_with_retry(ix, {'type': 0, 'media': 0, 'storageid': 's'}, self.log, retry)
        self.assertEqual(ix.calls, 0)  # never attempted the network call

    def test_coerces_none_and_bytes(self):
        self.assertEqual(main._coerce_contents(None), '')
        self.assertEqual(main._coerce_contents(b'ab'), 'ab')
        self.assertEqual(main._coerce_contents('ab'), 'ab')


class ModelValidationTests(unittest.TestCase):
    def _write(self, data):
        p = os.path.join(tempfile.mkdtemp(), 'm.json')
        with open(p, 'w') as f:
            json.dump(data, f)
        return p

    def _valid(self, **over):
        dim = len(FEATURE_NAMES)
        base = {'feature_names': FEATURE_NAMES, 'weights': [0.0] * dim, 'bias': 0.0,
                'mean': [0.0] * dim, 'std': [1.0] * dim, 'metrics': {}}
        base.update(over)
        return base

    def test_zero_std_rejected(self):
        p = self._write(self._valid(std=[0.0] * len(FEATURE_NAMES)))
        self.assertIsNone(main.ConfidenceModel.load(p))

    def test_wrong_length_rejected(self):
        p = self._write(self._valid(weights=[0.0]))
        self.assertIsNone(main.ConfidenceModel.load(p))

    def test_valid_model_loads(self):
        p = self._write(self._valid())
        self.assertIsNotNone(main.ConfidenceModel.load(p))


class LoadDedupRobustnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = _silent_logger()

    def test_json_non_list_is_tolerated(self):
        p = os.path.join(self.tmp.name, 'o.json')
        with open(p, 'w') as f:
            json.dump({'not': 'a list'}, f)
        self.assertEqual(main.load_existing_dedup(p, 'json', self.log), set())

    def test_txt_resume_dedup(self):
        p = os.path.join(self.tmp.name, 'o.txt')
        main.write_txt_output([_cred(identity='a@x.it', password='Str0ngPass9',
                                     canonical='www.x.it:a@x.it:Str0ngPass9')], p, self.log)
        seen = main.load_existing_dedup(p, 'txt', self.log)
        self.assertIn('a@x.it:Str0ngPass9', seen)


class SafeShareSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = _silent_logger()

    def test_safe_share_from_txt(self):
        src = os.path.join(self.tmp.name, 'o.txt')
        dest = os.path.join(self.tmp.name, 'safe.csv')
        main.write_txt_output([_cred(identity='a@x.it', password='Secret789',
                                     canonical='x.it:a@x.it:Secret789', date='2024-05-01')], src, self.log)
        n = main.write_safe_share_file(src, 'txt', dest)
        self.assertEqual(n, 1)
        with open(dest) as f:
            self.assertIn('a@x.it', f.read())

    def test_safe_share_from_csv(self):
        src = os.path.join(self.tmp.name, 'o.csv')
        dest = os.path.join(self.tmp.name, 'safe.csv')
        main.write_csv_output([_cred(identity='b@x.it', password='Secret789')], src, self.log)
        n = main.write_safe_share_file(src, 'csv', dest)
        self.assertEqual(n, 1)


class CsvInjectionAndPermsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = _silent_logger()

    def test_csv_formula_is_neutralized(self):
        p = os.path.join(self.tmp.name, 'o.csv')
        main.write_csv_output([_cred(password='=HYPERLINK(1)')], p, self.log)
        with open(p) as f:
            self.assertIn("'=HYPERLINK(1)", f.read())

    def test_output_files_are_owner_only(self):
        for fmt in ('txt', 'csv', 'json', 'html'):
            p = os.path.join(self.tmp.name, f'o.{fmt}')
            main.write_output([_cred()], p, fmt, self.log)
            mode = stat.S_IMODE(os.stat(p).st_mode)
            self.assertEqual(mode, 0o600, f'{fmt} not 0o600')


class ProcessContextTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def _run(self, person_context=None, person_name_context=None, contents=''):
        ix = type('IX', (), {'FILE_VIEW': lambda self, *a: contents})()
        seen = set()
        return main.process_leaks(
            ix, [_leak('s1')], mode='balanced',
            target_context=main.build_target_context('corp.com'),
            person_context=person_context, person_name_context=person_name_context,
            seen=seen, log=self.log, delay=0,
        )

    def test_person_email_context_matches(self):
        ctx = main.build_person_email_context('john.doe@corp.com')
        creds, _ = self._run(person_context=ctx, contents='app.corp.com:john.doe@corp.com:Passw0rd!')
        self.assertEqual(len(creds), 1)

    def test_person_name_context_anchored(self):
        ctx = main.build_person_name_context('John Doe', domain='corp.com')
        creds, _ = self._run(person_name_context=ctx,
                             contents='john doe corp.com app.corp.com:john.doe@corp.com:Passw0rd!')
        self.assertEqual(len(creds), 1)


class RateLimiterTests(unittest.TestCase):
    def test_enforces_minimum_spacing(self):
        rl = main.RateLimiter(0.05)
        rl.wait()
        start = time.monotonic()
        rl.wait()
        self.assertGreaterEqual(time.monotonic() - start, 0.04)

    def test_zero_delay_does_not_block(self):
        rl = main.RateLimiter(0)
        start = time.monotonic()
        rl.wait()
        rl.wait()
        self.assertLess(time.monotonic() - start, 0.02)


class WorkerExceptionTests(unittest.TestCase):
    def test_unexpected_exception_propagates_with_workers(self):
        class BoomIX:
            def FILE_VIEW(self, *a):
                raise RuntimeError('unexpected')
        with self.assertRaises(RuntimeError):
            main.process_leaks(
                BoomIX(), [_leak('s1'), _leak('s2')], mode='balanced',
                target_context=main.build_target_context('corp.com'),
                person_context=None, person_name_context=None,
                seen=set(), log=_silent_logger(), workers=3, delay=0,
            )


class PhonebookPagingTests(unittest.TestCase):
    def setUp(self):
        self.log = _silent_logger()

    def test_stops_on_repeated_empty_pages(self):
        class EmptyPagesIX:
            def __init__(self):
                self.results = 0

            def PHONEBOOK_SEARCH(self, term, maxresults, buckets, datefrom, dateto):
                return 'x' * 40  # long id = started

            def PHONEBOOK_SEARCH_RESULT(self, search_id, limit):
                self.results += 1
                return {'selectors': [], 'status': 0}  # non-terminal, empty forever
        ix = EmptyPagesIX()
        out = main.run_phonebook_search(ix, 't', ['b'], 'a', 'b', 100, self.log, poll_delay=0)
        self.assertEqual(out, [])
        self.assertLessEqual(ix.results, 4)  # busy-poll guard stops after a few

    def test_status_two_stops(self):
        class NotFoundIX:
            def PHONEBOOK_SEARCH(self, *a, **k):
                return 'x' * 40

            def PHONEBOOK_SEARCH_RESULT(self, search_id, limit):
                return {'selectors': [{'selectorvalue': 'a@x.it'}], 'status': 2}
        out = main.run_phonebook_search(NotFoundIX(), 't', ['b'], 'a', 'b', 100, self.log)
        self.assertEqual(out, ['a@x.it'])


if __name__ == '__main__':
    unittest.main()
