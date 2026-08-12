"""fireguard -- a simple, friendly manager for the Linux ``ufw`` firewall.

Public API::

    from fireguard import status, set_enabled, add_rule, delete_rule
    st = status()                     # a parsed Status snapshot (privileged)
    if not st.active:
        set_enabled(True)             # pkexec ufw --force enable
    add_rule("allow", port="22", proto="tcp")

Every function raises :class:`FireGuardError` (and only that) on failure, so the
CLI and the tkinter GUI have a single exception to catch.  The pure helpers
(:func:`parse_status`, :func:`build_rule_args`, ...) need no root and import on
any platform; the privileged operations shell out to ``ufw`` via
``pkexec``/``sudo``.  On a box without ufw, :func:`ufw_available` returns False
and callers degrade gracefully.  100% AI-built, open source, published on
QuickOpen (quickopen.ai).
"""

from __future__ import annotations

from .errors import FireGuardError
from .ufw import (
    ACTIONS,
    DIRECTIONS,
    POLICIES,
    PRESETS,
    PROTOCOLS,
    Rule,
    Status,
    add_rule,
    allow_app,
    app_list,
    build_rule_args,
    delete_rule,
    parse_app_list,
    parse_status,
    preset_args,
    reset,
    run_spec,
    set_default,
    set_enabled,
    status,
    ufw_available,
)

__version__ = "1.0.0"

__all__ = [
    "FireGuardError",
    "Rule",
    "Status",
    "ACTIONS",
    "POLICIES",
    "DIRECTIONS",
    "PROTOCOLS",
    "PRESETS",
    "parse_status",
    "parse_app_list",
    "build_rule_args",
    "preset_args",
    "ufw_available",
    "status",
    "set_enabled",
    "add_rule",
    "run_spec",
    "delete_rule",
    "set_default",
    "app_list",
    "allow_app",
    "reset",
    "__version__",
]
