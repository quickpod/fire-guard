"""QuickOpen app internationalisation — the vendored half.

Phase 3 of the multilingual programme (owner ask 2026-08-17: "add multilingual
capabilities to OS, all bundled apps and portal").

Every bundled app is a Python/Tk program with its strings written inline. This
module is copied into each app package the same way `aura.py` is, so an app
gains translation with two lines:

    from .qi18n import setup
    _ = setup("quickopen-plain-text-editor")

and then wraps its user-visible text in `_("...")`.

Design notes:
  * The language comes from the OS, not from an app setting. Quick OS's
    Language Support app sets LANG/LANGUAGE system-wide, and gettext already
    reads exactly those — so adding a language in one place translates every
    app at once, with no per-app preference to keep in sync.
  * `setup()` NEVER raises and never returns None. A missing catalogue, an
    unreadable locale directory or a malformed .mo yields the identity
    function, so an app can only ever fall back to English — never to a stack
    trace on a user's desktop.
  * Catalogue lookup order: an in-tree `locale/` directory next to the app
    package (so a developer sees translations without installing), then the
    system `/usr/share/locale` where the deb installs them.
"""
from __future__ import annotations

import gettext as _gettext
import os
from typing import Callable

__all__ = ["setup", "available_languages"]

_SYSTEM_LOCALE_DIR = "/usr/share/locale"


def _candidate_dirs(package_file: str | None) -> list[str]:
    dirs: list[str] = []
    if package_file:
        here = os.path.dirname(os.path.abspath(package_file))
        # in-tree during development: <package>/locale, then <repo>/locale
        dirs.append(os.path.join(here, "locale"))
        dirs.append(os.path.join(os.path.dirname(here), "locale"))
    dirs.append(_SYSTEM_LOCALE_DIR)
    return [d for d in dirs if os.path.isdir(d)]


def setup(domain: str, package_file: str | None = None) -> Callable[[str], str]:
    """Return the translation function for `domain`.

    `package_file` is normally `__file__` from the app package, used to find an
    in-tree catalogue. Returns `str -> str`; the identity function if nothing
    is installed for the current language.
    """
    for directory in _candidate_dirs(package_file):
        try:
            translation = _gettext.translation(domain, localedir=directory,
                                               fallback=False)
        except (OSError, AttributeError, ValueError):
            continue
        return translation.gettext
    # Nothing installed for this language — English, which IS the source text.
    return lambda message: message


def available_languages(domain: str, package_file: str | None = None) -> list[str]:
    """Languages with a compiled catalogue for `domain`, for an About box."""
    found: set[str] = set()
    for directory in _candidate_dirs(package_file):
        try:
            entries = os.listdir(directory)
        except OSError:
            continue
        for lang in entries:
            mo = os.path.join(directory, lang, "LC_MESSAGES", domain + ".mo")
            if os.path.isfile(mo):
                found.add(lang)
    return sorted(found)
