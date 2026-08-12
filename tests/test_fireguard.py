"""Deterministic, headless tests for the fireguard package.

These never touch a real firewall: the pure parsers and the rule-spec builder
run directly, and every command-construction test monkeypatches the single
subprocess seam (``ufw._execute``) to capture the argument vector.  Only
TEST-NET-1 (192.0.2.0/24, RFC 5737) addresses appear in fixtures.
"""

from __future__ import annotations

import pytest

import fireguard
from fireguard import (
    FireGuardError,
    build_rule_args,
    parse_app_list,
    parse_status,
    preset_args,
)
from fireguard import ufw as ufw_mod


# --------------------------------------------------------------------------- #
# Sample ufw output
# --------------------------------------------------------------------------- #
STATUS_VERBOSE = """\
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80,443/tcp                 ALLOW IN    Anywhere
3306                       DENY IN     192.0.2.0/24
22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

STATUS_NUMBERED = """\
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80,443/tcp                 ALLOW IN    Anywhere
[ 3] 3306                       DENY IN     192.0.2.0/24
[ 4] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""

STATUS_INACTIVE = "Status: inactive\n"

APP_LIST = """\
Available applications:
  Apache Full
  Apache Secure
  OpenSSH
  Nginx HTTP
"""


# --------------------------------------------------------------------------- #
# parse_status
# --------------------------------------------------------------------------- #
def test_parse_status_verbose_defaults_and_rules():
    st = parse_status(STATUS_VERBOSE)
    assert st.active is True
    assert st.logging == "on (low)"
    assert st.default_incoming == "deny"
    assert st.default_outgoing == "allow"
    assert st.default_routed == "disabled"
    assert len(st.rules) == 4
    first = st.rules[0]
    assert first.to == "22/tcp"
    assert first.action == "ALLOW IN"
    assert first.frm == "Anywhere"
    assert first.number is None  # verbose rows are not numbered


def test_parse_status_numbered_carries_numbers_and_v6():
    st = parse_status(STATUS_NUMBERED)
    assert [r.number for r in st.rules] == [1, 2, 3, 4]
    assert st.rules[2].action == "DENY IN"
    assert st.rules[2].frm == "192.0.2.0/24"
    assert st.rules[3].v6 is True  # "(v6)" rule flagged


def test_parse_status_inactive_and_empty():
    assert parse_status(STATUS_INACTIVE).active is False
    empty = parse_status("")
    assert empty.active is False and empty.rules == []
    # None must not raise either
    assert parse_status(None).rules == []


def test_parse_status_multiword_to_column():
    # App-profile rules put spaces in the To column; the action token still
    # anchors the split.
    st = parse_status("[ 1] Apache Full              ALLOW IN    Anywhere\n")
    assert st.rules[0].to == "Apache Full"
    assert st.rules[0].action == "ALLOW IN"


def test_parse_status_as_dict_roundtrip():
    d = parse_status(STATUS_NUMBERED).as_dict()
    assert d["active"] is True
    assert d["rules"][0]["number"] == 1
    assert d["rules"][0]["from"] == "Anywhere"


# --------------------------------------------------------------------------- #
# parse_app_list
# --------------------------------------------------------------------------- #
def test_parse_app_list_strips_header_and_sorts():
    apps = parse_app_list(APP_LIST)
    assert apps == ["Apache Full", "Apache Secure", "Nginx HTTP", "OpenSSH"]


def test_parse_app_list_empty():
    assert parse_app_list("") == []
    assert parse_app_list("Available applications:\n") == []


# --------------------------------------------------------------------------- #
# build_rule_args
# --------------------------------------------------------------------------- #
def test_build_simple_port_proto():
    assert build_rule_args("allow", port="22", proto="tcp") == ["allow", "22/tcp"]


def test_build_simple_port_only():
    assert build_rule_args("deny", port="8080") == ["deny", "8080"]


def test_build_app_profile():
    assert build_rule_args("allow", app="OpenSSH") == ["allow", "OpenSSH"]


def test_build_extended_from_to_port_proto():
    args = build_rule_args("deny", port="3306", proto="tcp",
                           from_addr="192.0.2.0/24")
    assert args == ["deny", "from", "192.0.2.0/24", "to", "any",
                    "port", "3306", "proto", "tcp"]


def test_build_extended_from_only_defaults_to_any():
    args = build_rule_args("allow", from_addr="192.0.2.5")
    assert args == ["allow", "from", "192.0.2.5", "to", "any"]


def test_build_delete_prefix():
    args = build_rule_args("allow", port="22", proto="tcp", delete=True)
    assert args == ["delete", "allow", "22/tcp"]


def test_build_rejects_bad_action():
    with pytest.raises(FireGuardError):
        build_rule_args("permit", port="22")


def test_build_rejects_bad_proto():
    with pytest.raises(FireGuardError):
        build_rule_args("allow", port="22", proto="sctp")


def test_build_rejects_empty_spec():
    with pytest.raises(FireGuardError):
        build_rule_args("allow")


def test_build_rejects_app_with_address():
    with pytest.raises(FireGuardError):
        build_rule_args("allow", app="OpenSSH", from_addr="192.0.2.5")


def test_presets_produce_expected_args():
    assert preset_args("Allow SSH") == ["allow", "22/tcp"]
    assert preset_args("Allow HTTPS") == ["allow", "443/tcp"]
    with pytest.raises(FireGuardError):
        preset_args("Allow Nonsense")


# --------------------------------------------------------------------------- #
# Operations — command construction with a mocked subprocess boundary
# --------------------------------------------------------------------------- #
@pytest.fixture()
def capture(monkeypatch):
    """Force ufw 'available', neutralize privilege prefix, and capture argv."""
    calls = []

    def fake_execute(argv, timeout=60):
        calls.append(list(argv))
        return 0, calls_return.get("out", ""), ""

    calls_return = {"out": ""}
    monkeypatch.setattr(ufw_mod, "ufw_available", lambda: True)
    monkeypatch.setattr(ufw_mod, "_ufw_path", lambda: "/usr/sbin/ufw")
    monkeypatch.setattr(ufw_mod, "_privilege_prefix", lambda: ["/usr/bin/pkexec"])
    monkeypatch.setattr(ufw_mod, "_execute", fake_execute)
    return calls, calls_return


def test_set_enabled_uses_force_and_pkexec(capture):
    calls, _ = capture
    ufw_mod.set_enabled(True)
    assert calls[-1] == ["/usr/bin/pkexec", "/usr/sbin/ufw", "--force", "enable"]
    ufw_mod.set_enabled(False)
    assert calls[-1][-2:] == ["--force", "disable"]


def test_add_rule_builds_and_elevates(capture):
    calls, _ = capture
    ufw_mod.add_rule("allow", port="22", proto="tcp")
    assert calls[-1] == ["/usr/bin/pkexec", "/usr/sbin/ufw", "allow", "22/tcp"]


def test_delete_rule_forces(capture):
    calls, _ = capture
    ufw_mod.delete_rule(3)
    assert calls[-1] == ["/usr/bin/pkexec", "/usr/sbin/ufw",
                         "--force", "delete", "3"]


def test_delete_rule_validates_number(capture):
    with pytest.raises(FireGuardError):
        ufw_mod.delete_rule("abc")
    with pytest.raises(FireGuardError):
        ufw_mod.delete_rule(0)


def test_run_spec_delete_gets_force(capture):
    calls, _ = capture
    ufw_mod.run_spec(["delete", "allow", "22/tcp"])
    assert calls[-1] == ["/usr/bin/pkexec", "/usr/sbin/ufw",
                         "--force", "delete", "allow", "22/tcp"]


def test_set_default_validates_and_builds(capture):
    calls, _ = capture
    ufw_mod.set_default("incoming", "deny")
    assert calls[-1][-3:] == ["default", "deny", "incoming"]
    with pytest.raises(FireGuardError):
        ufw_mod.set_default("sideways", "deny")
    with pytest.raises(FireGuardError):
        ufw_mod.set_default("incoming", "maybe")


def test_app_list_parses_output(capture):
    calls, ret = capture
    ret["out"] = APP_LIST
    names = ufw_mod.app_list()
    assert calls[-1][-2:] == ["app", "list"]
    assert "OpenSSH" in names


def test_allow_app_elevates(capture):
    calls, _ = capture
    ufw_mod.allow_app("OpenSSH")
    assert calls[-1] == ["/usr/bin/pkexec", "/usr/sbin/ufw", "allow", "OpenSSH"]


def test_status_single_prompt_merges_verbose_and_numbered(monkeypatch):
    seen = {}

    def fake_execute(argv, timeout=60):
        seen["argv"] = list(argv)
        return 0, STATUS_VERBOSE + "<<<FG>>>" + STATUS_NUMBERED, ""

    monkeypatch.setattr(ufw_mod, "ufw_available", lambda: True)
    monkeypatch.setattr(ufw_mod, "_ufw_path", lambda: "/usr/sbin/ufw")
    monkeypatch.setattr(ufw_mod, "_privilege_prefix", lambda: ["/usr/bin/pkexec"])
    monkeypatch.setattr(ufw_mod, "_execute", fake_execute)

    st = ufw_mod.status()
    # one elevated shell call, both queries inside it
    assert seen["argv"][:2] == ["/usr/bin/pkexec", "sh"]
    assert "status verbose" in seen["argv"][-1]
    assert "status numbered" in seen["argv"][-1]
    # defaults come from verbose, rule numbers from numbered
    assert st.default_incoming == "deny"
    assert [r.number for r in st.rules] == [1, 2, 3, 4]


# --------------------------------------------------------------------------- #
# Error paths
# --------------------------------------------------------------------------- #
def test_nonzero_exit_becomes_clean_error(monkeypatch):
    monkeypatch.setattr(ufw_mod, "ufw_available", lambda: True)
    monkeypatch.setattr(ufw_mod, "_ufw_path", lambda: "/usr/sbin/ufw")
    monkeypatch.setattr(ufw_mod, "_privilege_prefix", lambda: [])
    monkeypatch.setattr(ufw_mod, "_execute",
                        lambda argv, timeout=60: (1, "", "ERROR: Bad port"))
    with pytest.raises(FireGuardError) as ei:
        ufw_mod.add_rule("allow", port="99999999", proto="tcp")
    assert "Bad port" in str(ei.value)


def test_cancelled_pkexec_becomes_friendly_error(monkeypatch):
    monkeypatch.setattr(ufw_mod, "ufw_available", lambda: True)
    monkeypatch.setattr(ufw_mod, "_ufw_path", lambda: "/usr/sbin/ufw")
    monkeypatch.setattr(ufw_mod, "_privilege_prefix", lambda: ["/usr/bin/pkexec"])
    monkeypatch.setattr(ufw_mod, "_execute",
                        lambda argv, timeout=60: (126, "", ""))
    with pytest.raises(FireGuardError) as ei:
        ufw_mod.set_enabled(True)
    assert "Authorization" in str(ei.value)


def test_execute_missing_binary_becomes_error():
    # The real subprocess seam turns a missing binary into a clean error.
    with pytest.raises(FireGuardError):
        ufw_mod._execute(["/nonexistent/binary/fireguard-xyz", "status"])


def test_operations_raise_when_ufw_unavailable(monkeypatch):
    monkeypatch.setattr(ufw_mod, "ufw_available", lambda: False)
    with pytest.raises(FireGuardError):
        ufw_mod.status()
    with pytest.raises(FireGuardError):
        ufw_mod.set_enabled(True)


# --------------------------------------------------------------------------- #
# ufw_available + guiconfig
# --------------------------------------------------------------------------- #
def test_ufw_available_false_off_linux(monkeypatch):
    monkeypatch.setattr(ufw_mod.sys, "platform", "win32")
    assert ufw_mod.ufw_available() is False


def test_ufw_available_false_without_binary(monkeypatch):
    monkeypatch.setattr(ufw_mod.sys, "platform", "linux")
    monkeypatch.setattr(ufw_mod, "_ufw_path", lambda: None)
    assert ufw_mod.ufw_available() is False


def test_guiconfig_roundtrip(tmp_path, monkeypatch):
    from fireguard import guiconfig
    monkeypatch.setenv("FIREGUARD_HOME", str(tmp_path / "home"))
    assert guiconfig.get_theme() == "dark"      # default
    guiconfig.set_theme("light")
    assert guiconfig.get_theme() == "light"
    guiconfig.set_theme("bogus")                # ignored
    assert guiconfig.get_theme() == "light"


# --------------------------------------------------------------------------- #
# Headless GUI import + main()
# --------------------------------------------------------------------------- #
def test_gui_imports_without_display():
    # Importing the module must not create a Tk root or need customtkinter.
    from fireguard import gui
    assert gui.APP_NAME == "FireGuard"
    assert callable(gui.build_app)


def test_gui_main_returns_zero_headless(monkeypatch):
    from fireguard import gui
    # No DISPLAY -> Tk root creation fails -> main() degrades to 0, not a crash.
    monkeypatch.delenv("DISPLAY", raising=False)
    assert gui.main() == 0


def test_public_api_surface():
    for name in ("status", "set_enabled", "add_rule", "delete_rule",
                 "set_default", "app_list", "allow_app", "build_rule_args",
                 "parse_status", "FireGuardError"):
        assert hasattr(fireguard, name)
