"""Local, multi-key store for IntelX API keys.

Keys are kept in a single JSON file (default ``~/.config/credx/config.json``,
honoring ``XDG_CONFIG_HOME``) written with ``0600`` permissions in a ``0700``
directory, so other users on the host cannot read them. Several named keys can be
stored at once (one is "active"); credx resolves the active key, or one chosen by
name, when no ``-k`` flag or ``INTELX_API_KEY`` env var is given.

Pure standard library; no third-party dependencies. Functions take an optional
``path`` so they are easy to test in isolation.
"""
import json
import os
from typing import Any, Dict, Optional

DEFAULT_KEY_NAME = 'default'


def config_dir() -> str:
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')
    return os.path.join(base, 'credx')


def config_path() -> str:
    return os.path.join(config_dir(), 'config.json')


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Return ``{'active': name|None, 'keys': {name: key}}``, recovering from a
    missing or corrupt file by returning an empty store."""
    path = path or config_path()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    raw_keys = data.get('keys')
    keys: Dict[str, str] = {}
    if isinstance(raw_keys, dict):
        for name, key in raw_keys.items():
            if isinstance(name, str) and isinstance(key, str) and key:
                keys[name] = key

    active = data.get('active')
    if active not in keys:
        active = next(iter(keys), None)  # fall back to any stored key, or None
    return {'active': active, 'keys': keys}


def _atomic_write(path: str, data: Dict[str, Any]) -> None:
    """Write ``data`` as JSON to ``path`` with 0600 perms in a 0700 dir, atomically."""
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass  # best effort (e.g. non-POSIX filesystem)

    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def set_key(name: str, key: str, path: Optional[str] = None, make_active: bool = False) -> None:
    """Store ``key`` under ``name``. It becomes active if it is the first key, or
    when ``make_active`` is set; otherwise the active key is left unchanged."""
    path = path or config_path()
    cfg = load_config(path)
    cfg['keys'][name] = key
    if make_active or cfg.get('active') is None:
        cfg['active'] = name
    _atomic_write(path, cfg)


def use_key(name: str, path: Optional[str] = None) -> bool:
    """Make ``name`` the active key. Returns False if no such key is stored."""
    path = path or config_path()
    cfg = load_config(path)
    if name not in cfg['keys']:
        return False
    cfg['active'] = name
    _atomic_write(path, cfg)
    return True


def remove_key(name: str, path: Optional[str] = None) -> bool:
    """Delete the key named ``name``, reassigning ``active`` if needed. Returns
    False if no such key is stored."""
    path = path or config_path()
    cfg = load_config(path)
    if name not in cfg['keys']:
        return False
    del cfg['keys'][name]
    if cfg.get('active') == name:
        cfg['active'] = next(iter(cfg['keys']), None)
    _atomic_write(path, cfg)
    return True


def rename_key(old: str, new: str, path: Optional[str] = None) -> str:
    """Rename a saved key. Returns 'ok', 'missing' (no such key), or 'exists'
    (the new name is already taken)."""
    path = path or config_path()
    cfg = load_config(path)
    if old not in cfg['keys']:
        return 'missing'
    if new != old and new in cfg['keys']:
        return 'exists'
    cfg['keys'][new] = cfg['keys'].pop(old)
    if cfg.get('active') == old:
        cfg['active'] = new
    _atomic_write(path, cfg)
    return 'ok'


def clear_all(path: Optional[str] = None) -> None:
    """Remove every stored key."""
    _atomic_write(path or config_path(), {'active': None, 'keys': {}})


def get_key(name: Optional[str] = None, path: Optional[str] = None) -> Optional[str]:
    """Return the key named ``name``, or the active key when ``name`` is None."""
    cfg = load_config(path)
    if name is None:
        name = cfg.get('active')
    if name is None:
        return None
    return cfg['keys'].get(name)


def mask_key(key: str) -> str:
    """Return a display form that never reveals the full key."""
    if not key:
        return ''
    if len(key) <= 8:
        return '*' * len(key)
    return f"{key[:4]}…{key[-4:]}"
