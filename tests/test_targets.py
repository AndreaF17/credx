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
        self._orig_home = os.environ.get('CREDX_HOME')
        os.environ['CREDX_HOME'] = os.path.join(self.work.name, 'credxhome')

        self._orig_loader = main.load_intelx_client
        main.load_intelx_client = lambda: _BatchFakeIX

        def restore():
            main.load_intelx_client = self._orig_loader
            for var, orig in (('INTELX_API_KEY', self._orig_env), ('XDG_CONFIG_HOME', self._orig_xdg),
                              ('CREDX_HOME', self._orig_home)):
                if orig is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = orig
        self.addCleanup(restore)

    def pt(self, target):
        return os.path.join(main.output_root(), target, 'creds.json')

    def combined(self):
        return os.path.join(main.output_root(), '_batch', 'creds.json')

    def _read_json(self, path):
        import json
        with open(path, encoding='utf-8') as f:
            return json.load(f)

    def test_both_mode_writes_per_target_and_combined(self):
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(self.pt('a.com')))
        self.assertTrue(os.path.exists(self.pt('b.com')))
        self.assertTrue(os.path.exists(self.combined()))

        a = self._read_json(self.pt('a.com'))
        self.assertEqual(a[0]['identity'], 'admin')
        self.assertEqual(a[0]['target'], 'a.com')

        combined = self._read_json(self.combined())
        self.assertEqual({c['target'] for c in combined}, {'a.com', 'b.com'})

    def test_combined_only_mode_skips_per_target_files(self):
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--output-mode', 'combined', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.pt('a.com')))
        self.assertTrue(os.path.exists(self.combined()))

    def test_per_target_only_mode_skips_combined(self):
        rc = main.main(['-t', 'a.com,b.com', '-f', 'json', '--output-mode', 'per-target', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(self.pt('a.com')))
        self.assertFalse(os.path.exists(self.combined()))

    def test_single_target_unchanged(self):
        rc = main.main(['-t', 'a.com', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(self.pt('a.com')))
        self.assertFalse(os.path.exists(self.combined()))  # no combined for single

    def test_single_target_respects_explicit_output(self):
        dest = os.path.join(self.work.name, 'custom', 'myout.json')
        rc = main.main(['-t', 'a.com', '-o', dest, '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.exists(dest))

    def test_local_merges_with_intelx(self):
        os.makedirs('dumps', exist_ok=True)
        with open('dumps/x.txt', 'w', encoding='utf-8') as f:
            f.write('a.com:localuser:LocalPass9\n')
        rc = main.main(['-t', 'a.com', '--local', 'dumps', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        ids = {c['identity'] for c in self._read_json(self.pt('a.com'))}
        self.assertIn('admin', ids)      # from the IntelX fake
        self.assertIn('localuser', ids)  # from the local source

    def test_target_file_input(self):
        with open('targets.txt', 'w', encoding='utf-8') as f:
            f.write('# clients\na.com\nb.com\n')
        rc = main.main(['-t', 'targets.txt', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        combined = self._read_json(self.combined())
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
        self.assertTrue(os.path.exists(self.pt('a.com')))


class IterLocalDocumentsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        import logging
        self.log = logging.getLogger('t-local')
        self.log.addHandler(logging.NullHandler())

    def test_reads_text_skips_binary(self):
        d = self.tmp.name
        with open(os.path.join(d, 'a.txt'), 'w') as f:
            f.write('hello')
        with open(os.path.join(d, 'b.zip'), 'w') as f:
            f.write('binary-ish')
        names = [n for n, _c, _d in main.iter_local_documents(d, self.log)]
        self.assertTrue(any(n.endswith('a.txt') for n in names))
        self.assertFalse(any('b.zip' in n for n in names))

    def test_single_file(self):
        p = os.path.join(self.tmp.name, 'f.txt')
        with open(p, 'w') as f:
            f.write('content')
        docs = list(main.iter_local_documents(p, self.log))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0][1], 'content')
        self.assertTrue(docs[0][0].startswith('local:'))


class LocalSourceTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self._cwd = os.getcwd()
        os.chdir(self.work.name)
        self.addCleanup(lambda: os.chdir(self._cwd))
        self._env = os.environ.get('INTELX_API_KEY')
        os.environ.pop('INTELX_API_KEY', None)
        self._xdg = os.environ.get('XDG_CONFIG_HOME')
        os.environ['XDG_CONFIG_HOME'] = os.path.join(self.work.name, 'cfg')
        self._home = os.environ.get('CREDX_HOME')
        os.environ['CREDX_HOME'] = os.path.join(self.work.name, 'credxhome')

        def restore():
            for var, orig in (('INTELX_API_KEY', self._env), ('XDG_CONFIG_HOME', self._xdg),
                              ('CREDX_HOME', self._home)):
                if orig is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = orig
        self.addCleanup(restore)

        os.makedirs('dumps')
        with open('dumps/combo.txt', 'w', encoding='utf-8') as f:
            f.write('admin@corp.com:Sup3rSecret1\nx@other.com:nope\n')
        with open('dumps/leak.csv', 'w', encoding='utf-8') as f:
            f.write('email,password\ncarol@corp.com,CsvPass99\n')

    def _read(self, path):
        import json
        with open(path, encoding='utf-8') as f:
            return json.load(f)

    def test_local_only_offline_no_key(self):
        rc = main.main(['-t', 'corp.com', '--local', 'dumps', '-f', 'json', '--delay', '0'])
        self.assertEqual(rc, 0)
        creds = self._read(os.path.join(main.output_root(), 'corp.com', 'creds.json'))
        self.assertEqual({c['identity'] for c in creds}, {'admin@corp.com', 'carol@corp.com'})
        self.assertTrue(all(c['source'].startswith('local:') for c in creds))
        self.assertTrue(all(c['target'] == 'corp.com' for c in creds))

    def test_output_dirs_are_private(self):
        import stat
        main.main(['-t', 'corp.com', '--local', 'dumps', '-f', 'json', '--delay', '0'])
        root = main.output_root()
        for d in (os.path.dirname(root), root, os.path.join(root, 'corp.com')):
            mode = stat.S_IMODE(os.stat(d).st_mode)
            self.assertEqual(mode, 0o700, f"{d} is {oct(mode)} (should be 0o700)")

    def test_no_source_errors(self):
        rc = main.main(['-t', 'corp.com', '--delay', '0'])
        self.assertEqual(rc, 1)

    def test_missing_local_path_errors(self):
        rc = main.main(['-t', 'corp.com', '--local', 'does-not-exist', '--delay', '0'])
        self.assertEqual(rc, 2)


class StartupBannerTests(unittest.TestCase):
    def _args(self, **over):
        base = dict(
            model=None, include_subdomains=False, company_wide=False, expand_archives=False,
            phonebook=False, phonebook_search=False, usernames=False, safe_share=False,
            output_mode='both', range=24, mode='balanced', format='txt',
            workers=5, delay=0.2, maxresults=500, output=None,
        )
        base.update(over)
        import argparse as _argparse
        return _argparse.Namespace(**base)

    def _banner(self, args, targets, key_label, buckets, caps):
        import contextlib
        import io as _io
        err = _io.StringIO()
        with contextlib.redirect_stderr(err):
            main.print_startup_banner(
                args, targets, key_label, buckets, '2024-01-01 00:00:00', '2024-12-31 23:59:59', caps,
            )
        return err.getvalue()

    def test_banner_shows_config_and_credits(self):
        caps = {'name': 'Acme', 'paths': {'/intelligent/search': {'Credit': 95, 'CreditMax': 100}}}
        out = self._banner(self._args(), ['corp.com'], "saved 'default'", ['leaks.private', 'pastes'], caps)
        self.assertIn('credx', out)
        self.assertIn('corp.com', out)
        self.assertIn('exact domain', out)
        self.assertIn('95/100', out)

    def test_banner_matching_reflects_include_subdomains(self):
        out = self._banner(self._args(include_subdomains=True), ['corp.com'], 'env', ['pastes'], None)
        self.assertIn('incl. subdomains', out)

    def test_banner_warns_on_exhausted_credits(self):
        caps = {'paths': {'/intelligent/search': {'Credit': 0, 'CreditMax': 100}}}
        out = self._banner(self._args(), ['corp.com'], 'env', ['pastes'], caps)
        self.assertIn('no credits left', out)

    def test_banner_multi_target(self):
        out = self._banner(self._args(), ['a.com', 'b.com', 'c.com'], 'env', ['pastes'], None)
        self.assertIn('3 targets', out)


if __name__ == '__main__':
    unittest.main()

