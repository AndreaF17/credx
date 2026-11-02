"""Tests for multi-target input (-t as file / comma-list / single) and batch output."""
import os
import tempfile
import unittest

import main


class CollectTargetsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_single_target(self):
        self.assertEqual(main.collect_targets('corp.com'), ['corp.com'])

    def test_comma_list(self):
        self.assertEqual(
            main.collect_targets('a.com, b.com ,c.com'),
            ['a.com', 'b.com', 'c.com'],
        )

    def test_empty_or_none(self):
        self.assertEqual(main.collect_targets(None), [])
        self.assertEqual(main.collect_targets(''), [])
        self.assertEqual(main.collect_targets('   '), [])

    def test_dedup_case_insensitive_keeps_first(self):
        self.assertEqual(main.collect_targets('A.com,a.com,A.COM'), ['A.com'])

    def test_file_one_per_line_with_comments(self):
        path = os.path.join(self.tmp.name, 'targets.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('# a comment\n')
            f.write('corp.com\n')
            f.write('\n')
            f.write('john.doe@corp.com\n')
            f.write('  spaced.com  \n')
        self.assertEqual(
            main.collect_targets(path),
            ['corp.com', 'john.doe@corp.com', 'spaced.com'],
        )

    def test_file_takes_precedence_over_comma_detection(self):
        # An existing file is read as a file even though we also support comma-lists.
        path = os.path.join(self.tmp.name, 'list.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('only.com\n')
        self.assertEqual(main.collect_targets(path), ['only.com'])


class BatchArgTests(unittest.TestCase):
    def test_output_mode_default_both(self):
        args = main.parse_args(['-t', 'corp.com'])
        self.assertEqual(args.output_mode, 'both')

    def test_output_mode_choices(self):
        for mode in ('per-target', 'combined', 'both'):
            args = main.parse_args(['-t', 'corp.com', '--output-mode', mode])
            self.assertEqual(args.output_mode, mode)

    def test_output_mode_rejects_unknown(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['-t', 'corp.com', '--output-mode', 'nope'])


class _BatchFakeIX:
    """Fake IntelX: domain selector -> one leak; FILE_VIEW -> a matching cred line."""
    _RECORDS = {
        '@a.com': [{'storageid': 'A', 'type': 0, 'media': 0, 'bucket': 'b',
                    'name': 'leakA', 'date': '2024-01-01T00:00:00'}],
        '@b.com': [{'storageid': 'B', 'type': 0, 'media': 0, 'bucket': 'b',
                    'name': 'leakB', 'date': '2024-01-01T00:00:00'}],
    }
    _CONTENTS = {'A': 'a.com:admin:StrongPass1', 'B': 'b.com:root:StrongPass2'}

    def __init__(self, key=None):
        self.key = key

    def GET_CAPABILITIES(self):
        return {}

    def search(self, term, maxresults, buckets, datefrom, dateto):
        return {'records': self._RECORDS.get(term, [])}

    def FILE_VIEW(self, _type, _media, storageid, _bucket):
        return self._CONTENTS.get(storageid, '')


class BatchRunIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self._cwd = os.getcwd()
        os.chdir(self.work.name)
        self.addCleanup(lambda: os.chdir(self._cwd))

        self._orig_env = os.environ.get('INTELX_API_KEY')
        os.environ['INTELX_API_KEY'] = 'TESTKEY'
        self._orig_xdg = os.environ.get('XDG_CONFIG_HOME')
        os.environ['XDG_CONFIG_HOME'] = os.path.join(self.work.name, 'cfg')

        self._orig_loader = main.load_intelx_client
        main.load_intelx_client = lambda: _BatchFakeIX

        def restore():
            main.load_intelx_client = self._orig_loader
            if self._orig_env is None:
                os.environ.pop('INTELX_API_KEY', None)
            else:
                os.environ['INTELX_API_KEY'] = self._orig_env
            if self._orig_xdg is None:
                os.environ.pop('XDG_CONFIG_HOME', None)
            else:
                os.environ['XDG_CONFIG_HOME'] = self._orig_xdg
        self.addCleanup(restore)

    def _read_json(self, path):
        import json
        with open(path, encoding='utf-8') as f:
            return json.load(f)

    def test_both_mode_writes_per_target_and_combined(self):
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists('out/a.com-creds.json'))
        self.assertTrue(os.path.exists('out/b.com-creds.json'))
        self.assertTrue(os.path.exists('out/batch-creds.json'))

        a = self._read_json('out/a.com-creds.json')
        self.assertEqual(a[0]['identity'], 'admin')
        self.assertEqual(a[0]['target'], 'a.com')

        combined = self._read_json('out/batch-creds.json')
        self.assertEqual({c['target'] for c in combined}, {'a.com', 'b.com'})

    def test_combined_only_mode_skips_per_target_files(self):
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--output-mode', 'combined', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists('out/a.com-creds.json'))
        self.assertTrue(os.path.exists('out/batch-creds.json'))

    def test_per_target_only_mode_skips_combined(self):
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--output-mode', 'per-target', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists('out/a.com-creds.json'))
        self.assertFalse(os.path.exists('out/batch-creds.json'))

    def test_single_target_unchanged(self):
        rc = main.main(['-t', 'a.com', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists('out/a.com-creds.json'))
        self.assertFalse(os.path.exists('out/batch-creds.json'))  # no combined for single

    def test_target_file_input(self):
        with open('targets.txt', 'w', encoding='utf-8') as f:
            f.write('# clients\na.com\nb.com\n')
        rc = main.main(['-t', 'targets.txt', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        combined = self._read_json('out/batch-creds.json')
        self.assertEqual({c['target'] for c in combined}, {'a.com', 'b.com'})

    def test_single_target_write_failure_exits_one(self):
        orig = main.write_output

        def boom(*a, **k):
            raise OSError('disk full')

        main.write_output = boom  # restored below
        try:
            rc = main.main(['-t', 'a.com', '-f', 'json', '--delay', '0'])
        finally:
            main.write_output = orig
        self.assertEqual(rc, 1)

    def test_single_target_all_searches_failed_exits_two(self):
        class _FailIX:
            def __init__(self, key=None):
                pass

            def GET_CAPABILITIES(self):
                return {}

            def search(self, *a, **k):
                raise OSError('network down')

        main.load_intelx_client = lambda: _FailIX  # restored by fixture cleanup
        rc = main.main(['-t', 'a.com', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 2)

    def test_batch_continues_when_one_target_fails(self):
        class _PartialIX(_BatchFakeIX):
            def search(self, term, maxresults, buckets, datefrom, dateto):
                if term == '@b.com':
                    raise OSError('b is down')
                return super().search(term, maxresults, buckets, datefrom, dateto)

        main.load_intelx_client = lambda: _PartialIX
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)  # a.com succeeded
        self.assertTrue(os.path.exists('out/a.com-creds.json'))


if __name__ == '__main__':
    unittest.main()

