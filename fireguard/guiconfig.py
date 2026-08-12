r"""Tiny JSON-backed config for FireGuard's GUI (theme preference only).

This module owns the window's remembered theme (``light``/``dark``) and never
raises -- a corrupt or unreadable config must never stop the app from starting.

On Windows the base dir is ``%LOCALAPPDATA%\FireGuard``; elsewhere it falls
back to ``~/.fireguard``.  Setting ``FIREGUARD_HOME`` overrides both (used by
the test-suite to keep everything inside a tmp tree).
"""

from __future__ import annotations

import json
import os

APP_DIRNAME = "FireGuard"
CONFIG_NAME = "config.json"
VALID_THEMES = ("light", "dark")


def config_dir():
    r"""Base directory for FireGuard's config (created on demand by callers).

    Order of precedence: ``$FIREGUARD_HOME`` -> ``%LOCALAPPDATA%\FireGuard`` on
    Windows -> ``~/.fireguard`` everywhere else.
    """
    override = os.environ.get("FIREGUARD_HOME")
    if override:
        return override
    local = os.environ.get("LOCALAPPDATA")
    if local and os.name == "nt":
        return os.path.join(local, APP_DIRNAME)
    return os.path.join(os.path.expanduser("~"), "." + APP_DIRNAME.lower())


def config_path():
    return os.path.join(config_dir(), CONFIG_NAME)


def _defaults():
    return {"theme": "dark"}


def load():
    """Return the config dict, always with a valid ``theme`` key."""
    cfg = _defaults()
    try:
        with open(config_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("theme") in VALID_THEMES:
            cfg["theme"] = data["theme"]
    except Exception:
        pass  # missing/corrupt -> defaults; never fatal
    return cfg


def save(cfg):
    """Persist *cfg* (best-effort; failures are swallowed)."""
    try:
        os.makedirs(config_dir(), exist_ok=True)
        clean = {"theme": cfg.get("theme")
                 if cfg.get("theme") in VALID_THEMES else "dark"}
        tmp = config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2)
        os.replace(tmp, config_path())
    except Exception:
        pass


def get_theme():
    return load().get("theme", "dark")


def set_theme(theme):
    if theme not in VALID_THEMES:
        return
    cfg = load()
    cfg["theme"] = theme
    save(cfg)
