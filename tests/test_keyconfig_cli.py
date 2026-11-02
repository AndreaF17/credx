"""Tests for the `credx config` subcommand, key resolution, and usage display."""
import argparse
import contextlib
import io
import logging
import os
import tempfile
import unittest

import main
from custom import keystore


def _silent():
    log = logging.getLogger('test-keyconfig')
    log.addHandler(logging.NullHandler())
    return log


class _XdgTempMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig_xdg = os.environ.get('XDG_CONFIG_HOME')
        os.environ['XDG_CONFIG_HOME'] = self.tmp.name
        self._orig_key = os.environ.get('INTELX_API_KEY')
        os.environ.pop('INTELX_API_KEY', None)
        self.log = _silent()

        def restore():
            if self._orig_xdg is None:
                os.environ.pop('XDG_CONFIG_HOME', None)
            else:
                os.environ['XDG_CONFIG_HOME'] = self._orig_xdg
            if self._orig_key is not None:
                os.environ['INTELX_API_KEY'] = self._orig_key
        self.addCleanup(restore)


class ResolveApiKeyTests(_XdgTempMixin, unittest.TestCase):
    def _args(self, apikey=None, key_name=None):
        return argparse.Namespace(apikey=apikey, key_name=key_name)

    def test_flag_beats_everything(self):
        keystore.set_key('default', 'SAVED')
        os.environ['INTELX_API_KEY'] = 'ENV'
        self.assertEqual(main.resolve_api_key(self._args(apikey='FLAG'), self.log), 'FLAG')

    def test_env_beats_saved(self):
        keystore.set_key('default', 'SAVED')
        os.environ['INTELX_API_KEY'] = 'ENV'
        self.assertEqual(main.resolve_api_key(self._args(), self.log), 'ENV')

    def test_saved_active_used_when_no_flag_or_env(self):
        keystore.set_key('default', 'SAVEDKEY')
        self.assertEqual(main.resolve_api_key(self._args(), self.log), 'SAVEDKEY')

    def test_saved_selected_by_key_name(self):
        keystore.set_key('default', 'K1')
        keystore.set_key('client', 'K2')
        self.assertEqual(main.resolve_api_key(self._args(key_name='client'), self.log), 'K2')

    def test_none_when_nothing_configured(self):
        self.assertIsNone(main.resolve_api_key(self._args(), self.log))


class HandleConfigTests(_XdgTempMixin, unittest.TestCase):
    def _run(self, **kw):
        args = argparse.Namespace(command='config', **kw)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main.handle_config(args, self.log)
        return code, out.getvalue()

    def test_set_key_stores_and_activates_first(self):
        code, _ = self._run(config_action='set-key', key='KEY1', name='default', use=False)
        self.assertEqual(code, 0)
        self.assertEqual(keystore.get_key(), 'KEY1')

    def test_set_key_does_not_echo_full_key(self):
        _, out = self._run(config_action='set-key', key='SuperSecretKey123', name='default', use=False)
        self.assertNotIn('SuperSecretKey123', out)

    def test_list_marks_active_and_masks(self):
        keystore.set_key('default', 'abcd1234efgh5678')
        keystore.set_key('client', 'zzzz9999yyyy8888')
        code, out = self._run(config_action='list')
        self.assertEqual(code, 0)
        self.assertIn('default', out)
        self.assertIn('client', out)
        self.assertNotIn('abcd1234efgh5678', out)  # masked
        self.assertIn('*', out)  # active marker

    def test_use_switches_active(self):
        keystore.set_key('default', 'K1')
        keystore.set_key('client', 'K2')
        code, _ = self._run(config_action='use', name='client')
        self.assertEqual(code, 0)
        self.assertEqual(keystore.get_key(), 'K2')

    def test_use_unknown_key_errors(self):
        keystore.set_key('default', 'K1')
        code, _ = self._run(config_action='use', name='nope')
        self.assertEqual(code, 1)

    def test_show_masks_key(self):
        keystore.set_key('default', 'abcd1234efgh5678')
        code, out = self._run(config_action='show', name=None)
        self.assertEqual(code, 0)
        self.assertNotIn('abcd1234efgh5678', out)
        self.assertIn('abcd', out)  # masked prefix shown

    def test_clear_named(self):
        keystore.set_key('default', 'K1')
        keystore.set_key('client', 'K2')
        code, _ = self._run(config_action='clear', name='client', all=False)
        self.assertEqual(code, 0)
        self.assertIsNone(keystore.get_key('client'))

    def test_clear_all(self):
        keystore.set_key('default', 'K1')
        code, _ = self._run(config_action='clear', name=None, all=True)
        self.assertEqual(code, 0)
        self.assertEqual(keystore.load_config()['keys'], {})

    def test_clear_without_name_or_all_errors(self):
        code, _ = self._run(config_action='clear', name=None, all=False)
        self.assertEqual(code, 2)


class UsageTests(_XdgTempMixin, unittest.TestCase):
    def test_format_key_usage_renders_credits(self):
        caps = {
            'name': 'Acme',
            'paths': {
                '/intelligent/search': {'Credit': 95, 'CreditMax': 100},
                '/phonebook/search': {'Credit': 50, 'CreditMax': 50},
            },
        }
        text = main.format_key_usage(caps)
        self.assertIn('95', text)
        self.assertIn('100', text)
        self.assertIn('search', text)

    def test_format_key_usage_handles_empty(self):
        self.assertIsInstance(main.format_key_usage({}), str)
        self.assertIsInstance(main.format_key_usage(None), str)

    def test_usage_command_uses_selected_key(self):
        keystore.set_key('default', 'K1')
        keystore.set_key('client', 'CLIENTKEY')
        captured = {}

        class FakeIX:
            def __init__(self, key):
                captured['key'] = key

            def GET_CAPABILITIES(self):
                return {'name': 'Acme', 'paths': {'/intelligent/search': {'Credit': 10, 'CreditMax': 20}}}

        orig = main.load_intelx_client
        main.load_intelx_client = lambda: FakeIX
        try:
            args = argparse.Namespace(command='config', config_action='usage', name='client')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main.handle_config(args, self.log)
        finally:
            main.load_intelx_client = orig
        self.assertEqual(code, 0)
        self.assertEqual(captured['key'], 'CLIENTKEY')
        self.assertIn('10', out.getvalue())

    def test_usage_without_key_errors(self):
        orig = main.load_intelx_client
        main.load_intelx_client = lambda: (_ for _ in ()).throw(AssertionError('should not build client'))
        try:
            args = argparse.Namespace(command='config', config_action='usage', name=None)
            with contextlib.redirect_stdout(io.StringIO()):
                code = main.handle_config(args, self.log)
        finally:
            main.load_intelx_client = orig
        self.assertEqual(code, 1)


class ConfigArgParsingTests(unittest.TestCase):
    def test_config_set_key_parsed(self):
        args = main.parse_args(['config', 'set-key', 'MYKEY', '--name', 'work'])
        self.assertEqual(args.command, 'config')
        self.assertEqual(args.config_action, 'set-key')
        self.assertEqual(args.key, 'MYKEY')
        self.assertEqual(args.name, 'work')

    def test_config_does_not_require_target(self):
        args = main.parse_args(['config', 'list'])
        self.assertEqual(args.config_action, 'list')

    def test_scan_still_requires_target(self):
        with self.assertRaises(SystemExit):
            main.parse_args(['--phonebook'])  # no -t

    def test_scan_key_name_flag(self):
        args = main.parse_args(['-t', 'corp.com', '--key-name', 'client'])
        self.assertIsNone(args.command)
        self.assertEqual(args.key_name, 'client')


if __name__ == '__main__':
    unittest.main()
