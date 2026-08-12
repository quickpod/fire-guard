"""Command-line interface: ``python -m fireguard <command> ...``.

Commands::

    fireguard status
    fireguard enable
    fireguard disable
    fireguard allow <spec...>   [--from IP] [--to IP] [--port P] [--proto tcp|udp]
    fireguard deny  <spec...>   [--from IP] [--to IP] [--port P] [--proto tcp|udp]
    fireguard delete <number>
    fireguard default <incoming|outgoing|routed> <allow|deny|reject>
    fireguard apps [--allow NAME]

``allow``/``deny`` accept either a raw ufw spec (``fireguard allow 22/tcp``) or
the friendly flags (``fireguard allow --port 22 --proto tcp``).  Privileged
commands elevate with ``pkexec``/``sudo``.  Exits 0 on success and 1 (with a
clean ``error: ...`` line, never a traceback) on any :class:`FireGuardError`.
"""

from __future__ import annotations

import argparse
import sys

from . import (
    FireGuardError,
    allow_app,
    app_list,
    build_rule_args,
    delete_rule,
    run_spec,
    set_default,
    set_enabled,
    status,
    ufw_available,
)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def _print_status(st):
    print(f"Status: {'active' if st.active else 'inactive'}")
    if st.logging:
        print(f"Logging: {st.logging}")
    defs = []
    for label, val in (("incoming", st.default_incoming),
                       ("outgoing", st.default_outgoing),
                       ("routed", st.default_routed)):
        if val:
            defs.append(f"{val} ({label})")
    if defs:
        print("Default: " + ", ".join(defs))
    if not st.rules:
        print("\n(no rules)" if st.active else "")
        return
    print()
    width = max((len(r.to) for r in st.rules), default=4)
    for r in st.rules:
        num = f"[{r.number:>2}] " if r.number is not None else ""
        print(f"{num}{r.to:<{width}}  {r.action:<9}  {r.frm}")


# --------------------------------------------------------------------------- #
# command handlers
# --------------------------------------------------------------------------- #
def cmd_status(a):
    _print_status(status())


def cmd_enable(a):
    set_enabled(True)
    print("Firewall enabled.")


def cmd_disable(a):
    set_enabled(False)
    print("Firewall disabled.")


def _rule_cmd(a, action):
    if a.spec:
        run_spec([action, *a.spec])
    else:
        args = build_rule_args(action, port=a.port, proto=a.proto,
                               from_addr=getattr(a, "from"), to_addr=a.to)
        run_spec(args)
    print(f"Rule added: ufw {action} …")


def cmd_allow(a):
    _rule_cmd(a, "allow")


def cmd_deny(a):
    _rule_cmd(a, "deny")


def cmd_delete(a):
    delete_rule(a.number)
    print(f"Deleted rule {a.number}.")


def cmd_default(a):
    set_default(a.direction, a.policy)
    print(f"Default {a.direction} set to {a.policy}.")


def cmd_apps(a):
    if a.allow:
        allow_app(a.allow)
        print(f"Allowed application profile: {a.allow}")
        return
    names = app_list()
    if not names:
        print("(no application profiles)")
        return
    for n in names:
        print(n)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="fireguard",
        description="A friendly manager for the Linux ufw firewall.")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name, help, handler):
        sp = sub.add_parser(name, help=help)
        sp.set_defaults(func=handler)
        return sp

    add("status", "Show firewall status, defaults and numbered rules",
        cmd_status)
    add("enable", "Enable the firewall", cmd_enable)
    add("disable", "Disable the firewall", cmd_disable)

    for name, handler, verb in (("allow", cmd_allow, "Allow"),
                               ("deny", cmd_deny, "Deny")):
        s = add(name, f"{verb} traffic (raw spec or --port/--proto/--from/--to)",
                handler)
        s.add_argument("spec", nargs="*",
                       help="raw ufw spec, e.g. 22/tcp  (overrides the flags)")
        s.add_argument("--port", help="port or range, e.g. 22 or 8000:8100")
        s.add_argument("--proto", choices=("tcp", "udp"), help="protocol")
        s.add_argument("--from", dest="from", metavar="ADDR",
                       help="source address/CIDR (TEST-NET IPs in docs)")
        s.add_argument("--to", metavar="ADDR", help="destination address/CIDR")

    s = add("delete", "Delete a rule by its number (see 'status')", cmd_delete)
    s.add_argument("number", type=int)

    s = add("default", "Set a default policy for a direction", cmd_default)
    s.add_argument("direction", choices=("incoming", "outgoing", "routed"))
    s.add_argument("policy", choices=("allow", "deny", "reject"))

    s = add("apps", "List application profiles (or allow one)", cmd_apps)
    s.add_argument("--allow", metavar="NAME", help="allow this app profile")

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not ufw_available():
        print("error: ufw is not available on this system. FireGuard manages "
              "the Linux Uncomplicated Firewall (ufw); install it with "
              "'sudo apt install ufw' on a Linux host.", file=sys.stderr)
        return 1
    try:
        args.func(args)
    except FireGuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
