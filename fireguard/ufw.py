r"""The ufw wrapper: parsers, a rule-spec builder, and the privileged operations.

This is the whole engine behind FireGuard.  It is split into three layers so
the interesting bits are pure and testable without root or a real firewall:

* **Parsers** — :func:`parse_status` turns the text of ``ufw status [verbose]
  [numbered]`` into a structured :class:`Status`; :func:`parse_app_list` turns
  ``ufw app list`` into a list of profile names.  Pure functions, no I/O.
* **Rule-spec builder** — :func:`build_rule_args` turns friendly form fields
  (action, port, protocol, from/to, app profile) into the exact ``ufw``
  argument vector.  Pure, so the GUI form and the CLI share one source of truth
  and it can be unit-tested by asserting on the produced args.
* **Operations** — :func:`status`, :func:`set_enabled`, :func:`add_rule`,
  :func:`delete_rule`, :func:`set_default`, :func:`app_list`, :func:`allow_app`.
  These shell out to ``ufw`` (privileged ops via ``pkexec``/``sudo`` so the GUI
  works with no terminal) through the single :func:`_execute` boundary, which
  tests monkeypatch.

Everything raises :class:`FireGuardError` (and only that) on failure.  On a
non-Linux box or one without ``ufw`` installed the module still *imports* and
:func:`ufw_available` simply returns ``False`` -- callers degrade gracefully
with a clear "ufw not available" message instead of crashing.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .errors import FireGuardError

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
ACTIONS = ("allow", "deny", "reject", "limit")
POLICIES = ("allow", "deny", "reject")
DIRECTIONS = ("incoming", "outgoing", "routed")
PROTOCOLS = ("tcp", "udp")

# The action column of `ufw status` is one of these verbs + a direction token.
_ACTION_TOKENS = r"(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)"
# A status rule line, optionally numbered: "[ 1] 22/tcp  ALLOW IN  Anywhere".
_RULE_RE = re.compile(
    r"^(?:\[\s*(\d+)\]\s+)?(.+?)\s+" + _ACTION_TOKENS + r"\s*(.*)$"
)
_DEFAULT_RE = re.compile(
    r"(allow|deny|reject|disabled)\s*\((incoming|outgoing|routed)\)",
    re.IGNORECASE,
)

# Curated presets for the GUI's one-click buttons.  Each maps to build_rule_args
# kwargs so the preset and the manual form produce identical ufw arguments.
PRESETS = (
    ("Allow SSH", {"action": "allow", "port": "22", "proto": "tcp"}),
    ("Allow HTTP", {"action": "allow", "port": "80", "proto": "tcp"}),
    ("Allow HTTPS", {"action": "allow", "port": "443", "proto": "tcp"}),
    ("Allow HTTP/HTTPS", {"action": "allow", "port": "80,443", "proto": "tcp"}),
)


# --------------------------------------------------------------------------- #
# Structured status
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    """One firewall rule as shown by ``ufw status``."""

    number: Optional[int]      # position (from `numbered`), else None
    to: str                    # destination / port / app column
    action: str                # e.g. "ALLOW IN", "DENY IN", "LIMIT IN"
    frm: str                   # source column ("Anywhere", an IP, ...)
    v6: bool = False           # IPv6 rule?

    def as_dict(self):
        return {"number": self.number, "to": self.to, "action": self.action,
                "from": self.frm, "v6": self.v6}


@dataclass
class Status:
    """A parsed snapshot of the firewall."""

    active: bool = False
    logging: Optional[str] = None
    default_incoming: Optional[str] = None
    default_outgoing: Optional[str] = None
    default_routed: Optional[str] = None
    rules: List[Rule] = field(default_factory=list)

    def as_dict(self):
        return {
            "active": self.active,
            "logging": self.logging,
            "default_incoming": self.default_incoming,
            "default_outgoing": self.default_outgoing,
            "default_routed": self.default_routed,
            "rules": [r.as_dict() for r in self.rules],
        }


# --------------------------------------------------------------------------- #
# Parsers (pure -- no subprocess, no root)
# --------------------------------------------------------------------------- #
def parse_status(text: str) -> Status:
    """Parse the text of ``ufw status`` / ``status verbose`` / ``status numbered``.

    Tolerant of all three variants (and their concatenation): it reads the
    ``Status:``, ``Logging:`` and ``Default:`` header lines when present and
    every rule row, whether or not the rows are ``[ n]``-numbered.  Returns a
    :class:`Status`; an empty/None input yields an inactive status with no
    rules (never raises).
    """
    st = Status()
    if not text:
        return st

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()

        if low.startswith("status:"):
            # NB: "inactive" contains "active" — check the negative first.
            st.active = "inactive" not in low and "active" in low
            continue
        if low.startswith("logging:"):
            st.logging = line.split(":", 1)[1].strip() or None
            continue
        if low.startswith("default:"):
            for policy, direction in _DEFAULT_RE.findall(line):
                setattr(st, "default_" + direction.lower(), policy.lower())
            continue
        if low.startswith("new profiles:"):
            continue
        # Skip the table header + underline rows.
        if low.startswith("to ") or low.startswith("--"):
            continue

        m = _RULE_RE.match(line)
        if not m:
            continue
        num, to_col, verb, direction, from_col = m.groups()
        to_col = (to_col or "").strip()
        from_col = (from_col or "").strip() or "Anywhere"
        v6 = "(v6)" in to_col or "(v6)" in from_col
        st.rules.append(Rule(
            number=int(num) if num else None,
            to=to_col,
            action=f"{verb} {direction}",
            frm=from_col,
            v6=v6,
        ))
    return st


def parse_app_list(text: str) -> List[str]:
    """Parse ``ufw app list`` output into a sorted list of profile names.

    The command prints a header line ("Available applications:") followed by
    one profile name per line, indented.  Unknown/blank lines are ignored.
    """
    apps: List[str] = []
    if not text:
        return apps
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("available applications"):
            continue
        apps.append(line)
    return sorted(dict.fromkeys(apps))


# --------------------------------------------------------------------------- #
# Rule-spec builder (pure)
# --------------------------------------------------------------------------- #
def build_rule_args(
    action: str,
    *,
    port: Optional[str] = None,
    proto: Optional[str] = None,
    from_addr: Optional[str] = None,
    to_addr: Optional[str] = None,
    app: Optional[str] = None,
    delete: bool = False,
) -> List[str]:
    """Turn friendly fields into a ``ufw`` argument vector (no leading ``ufw``).

    Examples::

        build_rule_args("allow", port="22", proto="tcp")
            -> ["allow", "22/tcp"]
        build_rule_args("allow", app="OpenSSH")
            -> ["allow", "OpenSSH"]
        build_rule_args("deny", port="3306", from_addr="192.0.2.0/24")
            -> ["deny", "from", "192.0.2.0/24", "to", "any", "port", "3306"]
        build_rule_args("allow", port="22", proto="tcp", delete=True)
            -> ["delete", "allow", "22/tcp"]

    A ``from``/``to`` restriction forces ufw's *extended* grammar; a bare
    port/proto or app profile uses the *simple* grammar.  Raises
    :class:`FireGuardError` on an unusable combination.
    """
    action = (action or "").strip().lower()
    if action not in ACTIONS:
        raise FireGuardError(
            f"Unknown action {action!r} (expected one of {', '.join(ACTIONS)}).")

    proto = (proto or "").strip().lower() or None
    if proto and proto not in PROTOCOLS:
        raise FireGuardError(
            f"Unknown protocol {proto!r} (expected tcp or udp).")

    port = (str(port).strip() if port not in (None, "") else None)
    from_addr = (from_addr or "").strip() or None
    to_addr = (to_addr or "").strip() or None
    app = (app or "").strip() or None

    args: List[str] = [action]
    extended = bool(from_addr or to_addr)

    if app:
        if extended:
            raise FireGuardError(
                "An app profile can't be combined with from/to addresses.")
        args.append(app)
    elif extended:
        args += ["from", from_addr or "any", "to", to_addr or "any"]
        if port:
            args += ["port", port]
        if proto:
            args += ["proto", proto]
    elif port:
        args.append(f"{port}/{proto}" if proto else port)
    else:
        raise FireGuardError(
            "Give a port, an app profile, or a from/to address for the rule.")

    if delete:
        args.insert(0, "delete")
    return args


def preset_args(name: str) -> List[str]:
    """Return the ``ufw`` args for a named preset (see :data:`PRESETS`)."""
    for label, kwargs in PRESETS:
        if label == name:
            return build_rule_args(**kwargs)
    raise FireGuardError(f"Unknown preset {name!r}.")


# --------------------------------------------------------------------------- #
# Environment / availability
# --------------------------------------------------------------------------- #
def _ufw_path() -> Optional[str]:
    """Absolute path to the ``ufw`` binary, or None if not installed."""
    found = shutil.which("ufw")
    if found:
        return found
    for cand in ("/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw"):
        if os.path.exists(cand):
            return cand
    return None


def ufw_available() -> bool:
    """True only on a Linux host that actually has ``ufw`` installed.

    Everything privileged funnels through here first, so on Windows/macOS or a
    stripped container the app stays importable and degrades with a clear
    message rather than raising deep in subprocess land.
    """
    return sys.platform.startswith("linux") and _ufw_path() is not None


def _privilege_prefix() -> List[str]:
    """The command prefix that gains root for a privileged ufw call.

    Prefers ``pkexec`` (pops a graphical polkit prompt, so the GUI needs no
    terminal); falls back to non-interactive ``sudo -n`` when pkexec is absent;
    and, if already running as root, needs nothing.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    pkexec = shutil.which("pkexec")
    if pkexec:
        return [pkexec]
    sudo = shutil.which("sudo")
    if sudo:
        return [sudo, "-n"]
    return []


# --------------------------------------------------------------------------- #
# Subprocess boundary (the single seam tests monkeypatch)
# --------------------------------------------------------------------------- #
def _execute(argv: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """Run *argv* and return ``(returncode, stdout, stderr)``.

    The one and only place fireguard shells out.  Tests replace this to assert
    on the argument vector without touching a real firewall.
    """
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise FireGuardError(f"Command not found: {argv[0]} ({exc}).")
    except subprocess.TimeoutExpired:
        raise FireGuardError("Timed out waiting for ufw to respond.")
    except Exception as exc:  # pragma: no cover - defensive
        raise FireGuardError(f"Could not run ufw: {exc}.")
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _run_ufw(args: List[str], privileged: bool = False) -> str:
    """Build the ufw command line, run it, and return stdout (or raise).

    A non-zero exit, or a ``pkexec``-was-cancelled exit (126/127), becomes a
    clean :class:`FireGuardError`.
    """
    if not ufw_available():
        raise FireGuardError(
            "ufw is not available on this system. FireGuard manages the "
            "Uncomplicated Firewall (ufw), which runs on Linux only.")
    path = _ufw_path()
    prefix = _privilege_prefix() if privileged else []
    argv = [*prefix, path, *args]
    rc, out, err = _execute(argv)
    if rc != 0:
        detail = (err or out).strip()
        if privileged and rc in (126, 127) and not detail:
            raise FireGuardError(
                "Authorization was declined or unavailable, so the change was "
                "not applied.")
        raise FireGuardError(detail or f"ufw exited with status {rc}.")
    return out


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #
def status() -> Status:
    """Return the current firewall :class:`Status` (privileged).

    Runs verbose + numbered in a single elevated call so the caller gets both
    the default policies/logging *and* the ``[ n]`` rule numbers used for
    deletion -- from one authorization prompt.
    """
    if not ufw_available():
        raise FireGuardError(
            "ufw is not available on this system. FireGuard manages the "
            "Uncomplicated Firewall (ufw), which runs on Linux only.")
    path = _ufw_path()
    prefix = _privilege_prefix()
    # One prompt, two queries: verbose (defaults/logging) + numbered (numbers).
    script = f"{_sh_quote(path)} status verbose; echo '<<<FG>>>'; " \
             f"{_sh_quote(path)} status numbered"
    argv = [*prefix, "sh", "-c", script] if prefix else ["sh", "-c", script]
    rc, out, err = _execute(argv)
    if rc != 0:
        detail = (err or out).strip()
        if rc in (126, 127) and not detail:
            raise FireGuardError(
                "Authorization was declined, so the firewall status could not "
                "be read (reading ufw status requires root).")
        raise FireGuardError(detail or f"Could not read ufw status ({rc}).")
    verbose, _, numbered = out.partition("<<<FG>>>")
    merged = parse_status(verbose)                 # defaults + logging + active
    numbered_rules = parse_status(numbered).rules  # rules carrying [ n] numbers
    if numbered_rules:
        merged.rules = numbered_rules
    return merged


def set_enabled(enabled: bool) -> str:
    """Enable or disable the firewall (privileged).  ``--force`` skips prompts."""
    action = "enable" if enabled else "disable"
    return _run_ufw(["--force", action], privileged=True)


def add_rule(action="allow", *, port=None, proto=None, from_addr=None,
             to_addr=None, app=None) -> str:
    """Add a rule from friendly fields (privileged)."""
    args = build_rule_args(action, port=port, proto=proto, from_addr=from_addr,
                           to_addr=to_addr, app=app)
    return _run_ufw(args, privileged=True)


def run_spec(tokens: List[str]) -> str:
    """Run a raw ufw rule spec, e.g. ``["allow", "22/tcp"]`` (privileged).

    Used by the CLI so a spec typed the way ``ufw`` expects it passes straight
    through.  ``--force`` is added so a ``delete`` spec is not left waiting on a
    confirmation prompt.
    """
    if not tokens:
        raise FireGuardError("No rule specified.")
    args = list(tokens)
    if args and args[0] == "delete":
        args.insert(0, "--force")
    return _run_ufw(args, privileged=True)


def delete_rule(number: int) -> str:
    """Delete rule *number* (as shown by ``ufw status numbered``) (privileged)."""
    try:
        n = int(number)
    except (TypeError, ValueError):
        raise FireGuardError(f"Rule number must be an integer, got {number!r}.")
    if n < 1:
        raise FireGuardError("Rule numbers start at 1.")
    return _run_ufw(["--force", "delete", str(n)], privileged=True)


def set_default(direction: str, policy: str) -> str:
    """Set a default policy, e.g. ``set_default("incoming", "deny")`` (privileged)."""
    direction = (direction or "").strip().lower()
    policy = (policy or "").strip().lower()
    if direction not in DIRECTIONS:
        raise FireGuardError(
            f"Direction must be one of {', '.join(DIRECTIONS)}.")
    if policy not in POLICIES:
        raise FireGuardError(
            f"Default policy must be one of {', '.join(POLICIES)}.")
    return _run_ufw(["default", policy, direction], privileged=True)


def app_list() -> List[str]:
    """List available application profiles (privileged)."""
    out = _run_ufw(["app", "list"], privileged=True)
    return parse_app_list(out)


def allow_app(name: str) -> str:
    """Allow an application profile by name (privileged)."""
    name = (name or "").strip()
    if not name:
        raise FireGuardError("Choose an application profile first.")
    return _run_ufw(build_rule_args("allow", app=name), privileged=True)


def reset() -> str:
    """Disable the firewall and remove all rules (privileged)."""
    return _run_ufw(["--force", "reset"], privileged=True)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _sh_quote(s: str) -> str:
    import shlex
    return shlex.quote(s)
