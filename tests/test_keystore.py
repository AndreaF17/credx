"""Tests for the multi-key API-key store (custom/keystore.py)."""
import os
import stat
import tempfile
import unittest

from custom import keystore


class KeystoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'sub', 'config.json')

    def test_missing_config_is_empty(self):
        cfg = keystore.load_config(self.path)
        self.assertEqual(cfg['keys'], {})
        self.assertIsNone(cfg['active'])

    def test_first_key_becomes_active(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        self.assertEqual(keystore.get_key(path=self.path), 'KEY1')
        self.assertEqual(keystore.load_config(self.path)['active'], 'default')

    def test_second_key_does_not_switch_active_by_default(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        keystore.set_key('client', 'KEY2', path=self.path)
        self.assertEqual(keystore.load_config(self.path)['active'], 'default')
        self.assertEqual(keystore.get_key('client', path=self.path), 'KEY2')

    def test_set_key_with_use_switches_active(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        keystore.set_key('client', 'KEY2', path=self.path, make_active=True)
        self.assertEqual(keystore.load_config(self.path)['active'], 'client')

    def test_use_key_switches_active(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        keystore.set_key('client', 'KEY2', path=self.path)
        self.assertTrue(keystore.use_key('client', path=self.path))
        self.assertEqual(keystore.get_key(path=self.path), 'KEY2')

    def test_use_unknown_key_returns_false(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        self.assertFalse(keystore.use_key('nope', path=self.path))

    def test_remove_key_reassigns_active(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        keystore.set_key('client', 'KEY2', path=self.path)
        keystore.use_key('client', path=self.path)
        self.assertTrue(keystore.remove_key('client', path=self.path))
        # active fell back to a remaining key
        self.assertEqual(keystore.load_config(self.path)['active'], 'default')

    def test_remove_unknown_key_returns_false(self):
        self.assertFalse(keystore.remove_key('nope', path=self.path))

    def test_clear_all(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        keystore.clear_all(path=self.path)
        cfg = keystore.load_config(self.path)
        self.assertEqual(cfg['keys'], {})
        self.assertIsNone(cfg['active'])

    def test_get_named_key(self):
        keystore.set_key('a', 'KEYA', path=self.path)
        keystore.set_key('b', 'KEYB', path=self.path)
        self.assertEqual(keystore.get_key('b', path=self.path), 'KEYB')

    def test_get_unknown_named_key_is_none(self):
        keystore.set_key('a', 'KEYA', path=self.path)
        self.assertIsNone(keystore.get_key('missing', path=self.path))

    def test_config_file_is_0600(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_config_dir_is_0700(self):
        keystore.set_key('default', 'KEY1', path=self.path)
        mode = stat.S_IMODE(os.stat(os.path.dirname(self.path)).st_mode)
        self.assertEqual(mode, 0o700)

    def test_corrupt_config_is_treated_as_empty(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w', encoding='utf-8') as f:
            f.write('{ not json')
        cfg = keystore.load_config(self.path)
        self.assertEqual(cfg['keys'], {})

    def test_mask_key(self):
        self.assertEqual(keystore.mask_key('abcd1234efgh5678'), 'abcd…5678')
        self.assertNotIn('1234efgh', keystore.mask_key('abcd1234efgh5678'))
        self.assertEqual(keystore.mask_key('short'), '*****')
        self.assertEqual(keystore.mask_key(''), '')


if __name__ == '__main__':
    unittest.main()
