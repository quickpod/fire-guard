#!/usr/bin/env python3
r"""FireGuard -- an Aura (QuickOpen design system) GUI over the ``fireguard`` API.

A single Aura window for the Linux ``ufw`` firewall:

  * **Status** — a big Active/Inactive card with an enable/disable switch, the
    default in/out/routed policies, and the numbered rule list with a
    *Delete rule* action.
  * **Add rule** — one-click presets (Allow SSH / HTTP / HTTPS) plus a friendly
    form (allow/deny/reject/limit · port · protocol · optional from/to).
  * **Defaults** — set the default incoming / outgoing / routed policy.
  * **Apps** — list ``ufw`` application profiles and allow one.
  * **About**.

Design goals baked in here (mirrors the QuickOpen house style):
  * built on the vendored ``fireguard/aura.py`` design system.  Runtime deps:
    ``customtkinter`` (+ ``darkdetect``) — declared in requirements.txt; the
    PyInstaller build adds ``--collect-all customtkinter``.
  * Importing this module does nothing.  Only :func:`main` builds a root window,
    and it degrades gracefully (prints a message, returns 0) with no display or
    with customtkinter missing.
  * Frozen-exe safe: bundled assets resolve via ``sys._MEIPASS`` / the exe dir
    when ``sys.frozen`` is set -- never ``__file__``.
  * Every privileged ufw call (status, enable/disable, add/delete, defaults,
    app-allow) runs on a background thread via ``pkexec``; results are
    marshalled back with ``self.after`` and errors land in the Aura status bar,
    never as a traceback.

100% AI-built, open source, published on QuickOpen (quickopen.ai).
"""

from __future__ import annotations

import os
import sys
import threading

# tkinter/customtkinter are imported lazily inside main()/build_app so merely
# importing this module (e.g. during packaging or on a headless CI box) never
# fails.

APP_NAME = "FireGuard"
APP_VERSION = "1.0.0"
WINDOW_TITLE = "FireGuard — by QuickOpen (quickopen.ai)"
PROJECT_URL = "https://quickopen.ai"
ACCENT = "#17914b"      # green — security; publish/specs/fire-guard.json


# ---------------------------------------------------------------------------
# Asset / frozen handling  +  small OS helper
# ---------------------------------------------------------------------------
def asset_path(name):
    """Locate a bundled asset from source OR a PyInstaller one-file build."""
    roots = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(meipass)
        roots.append(os.path.dirname(os.path.abspath(sys.executable)))
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        roots += [here, os.path.dirname(here), os.getcwd()]
    for root in roots:
        candidate = os.path.join(root, name)
        if os.path.exists(candidate):
            return candidate
    return None


def open_with_default_app(path):
    """Open a URL/file with the OS default application, guarded."""
    try:
        if hasattr(os, "startfile"):
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            import subprocess
            subprocess.Popen(["open", path])
        else:
            import subprocess
            subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The app (built lazily; tkinter/customtkinter imported only inside build_app)
# ---------------------------------------------------------------------------
def build_app():
    """Construct and return the App class bound to live GUI imports.

    Kept inside a function so this module imports cleanly without a display
    (and without customtkinter installed).
    """
    import tkinter as tk
    from tkinter import ttk
    import customtkinter as ctk

    from . import aura, guiconfig
    from . import ufw as ufw_mod
    from .errors import FireGuardError

    class App(aura.AuraApp):
        def __init__(self):
            super().__init__(
                title=WINDOW_TITLE, app_name=APP_NAME, accent=ACCENT,
                theme=guiconfig.get_theme(),
                icon_png=asset_path("fire-guard.png"), version=APP_VERSION,
                tagline="ufw firewall",
                on_theme_change=guiconfig.set_theme,
                size=(1040, 680), min_size=(880, 560))

            self._status = None          # last fetched fireguard.Status
            self._busy = False           # a privileged op is in flight
            self._sync_toggle = False    # suppress switch-command during sync
            self._img_refs_gui = []

            self._set_icon()
            self._build_menu()
            self.add_section("status", "Status", "⬢", self._build_status)
            self.add_section("rules", "Add rule", "⊞", self._build_rules)
            self.add_section("defaults", "Defaults", "⚙", self._build_defaults)
            self.add_section("apps", "Apps", "▦", self._build_apps)
            self.add_section("about", "About", "◉", self._build_about)
            self.show("status")
            self.protocol("WM_DELETE_WINDOW", self.destroy)

            if not ufw_mod.ufw_available():
                self.set_error(
                    "ufw is not available here — FireGuard manages the Linux "
                    "firewall (install it with “sudo apt install ufw”).")
            else:
                self.set_status("Ready — press Refresh to read the firewall.")

        # ---- assets / icon
        def _set_icon(self):
            try:
                ico = asset_path("fire-guard.ico")
                if ico and os.name == "nt":
                    self.iconbitmap(ico)
                    return
            except Exception:
                pass
            try:
                png = asset_path("fire-guard.png")
                if png:
                    img = tk.PhotoImage(file=png)
                    self._img_refs_gui.append(img)
                    self.iconphoto(True, img)
            except Exception:
                pass  # icon is cosmetic; never block launch

        # ---- menu
        def _build_menu(self):
            bar = tk.Menu(self)
            filem = tk.Menu(bar, tearoff=0)
            filem.add_command(label="Refresh status",
                              command=self._refresh_status)
            filem.add_separator()
            filem.add_command(label="Exit", command=self.destroy)
            bar.add_cascade(label="File", menu=filem)

            viewm = tk.Menu(bar, tearoff=0)
            viewm.add_command(
                label="Toggle dark mode",
                command=lambda: self.set_theme(
                    "light" if self.theme == "dark" else "dark"))
            bar.add_cascade(label="View", menu=viewm)

            helpm = tk.Menu(bar, tearoff=0)
            helpm.add_command(label="About", command=lambda: self.show("about"))
            helpm.add_command(label="Open project page (quickopen.ai)",
                              command=lambda: open_with_default_app(PROJECT_URL))
            bar.add_cascade(label="Help", menu=helpm)
            self.configure(menu=bar)

        # ---- privileged-op plumbing (all ufw calls funnel through here) ----
        def _run_async(self, fn, on_ok, working="Working…"):
            """Run privileged *fn* off-thread; marshal ok/err to the UI thread.

            *on_ok(result)* runs on the UI thread on success; any
            FireGuardError (or unexpected error) becomes a status-bar error.
            """
            if self._busy:
                return
            if not ufw_mod.ufw_available():
                self.set_error(
                    "ufw is not available on this system (Linux only).")
                return
            self._busy = True
            self.set_status(working, kind="working")

            def work():
                try:
                    res, err = fn(), None
                except FireGuardError as exc:
                    res, err = None, str(exc)
                except Exception as exc:  # never leak a traceback
                    res, err = None, f"Unexpected error: {exc}"

                def done():
                    self._busy = False
                    if err is not None:
                        self.set_error(err)
                    else:
                        on_ok(res)
                self.after(0, done)

            threading.Thread(target=work, daemon=True).start()

        # =================================================================
        # Status section
        # =================================================================
        def _build_status(self, frame):
            card = aura.Card(frame, title="Firewall")
            card.pack(fill="x", pady=(0, 14))

            row = ctk.CTkFrame(card.body, fg_color="transparent")
            row.pack(fill="x")
            self._state_dot = ctk.CTkLabel(row, text="●", font=aura.font(20),
                                           text_color=aura.mix(ACCENT, "#808b9b",
                                                               0.5))
            self._state_dot.pack(side="left", padx=(0, 10))
            self._state_lbl = aura.Heading(row, "Unknown")
            self._state_lbl.pack(side="left")
            self._toggle = aura.Switch(row, text="Enabled",
                                       command=self._on_toggle)
            self._toggle.pack(side="right")

            self._defaults_lbl = aura.Caption(
                card.body, "Press Refresh to read the current policy.")
            self._defaults_lbl.pack(anchor="w", pady=(12, 0))
            self._logging_lbl = aura.Caption(card.body, "")
            self._logging_lbl.pack(anchor="w", pady=(2, 0))

            rules = aura.Card(frame, title="Rules")
            rules.pack(fill="both", expand=True)
            body = ctk.CTkFrame(rules.body, fg_color="transparent")
            body.pack(fill="both", expand=True)
            cols = ("num", "to", "action", "from")
            self.tree = ttk.Treeview(body, columns=cols, show="headings",
                                     selectmode="browse")
            for cid, label, width, stretch in (
                ("num", "#", 46, False),
                ("to", "To / port", 300, True),
                ("action", "Action", 130, False),
                ("from", "From", 260, True),
            ):
                self.tree.heading(cid, text=aura.spaced(label), anchor="w")
                self.tree.column(cid, width=width, stretch=stretch, anchor="w")
            sb = ttk.Scrollbar(body, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            sb.pack(side="right", fill="y")
            self.tree.pack(side="left", fill="both", expand=True)

            aura.AuraButton(self.statusbar.actions, "Refresh", kind="secondary",
                            height=30, command=self._refresh_status).pack(
                side="left")
            aura.AuraButton(self.statusbar.actions, "Delete rule",
                            kind="danger", height=30,
                            command=self._delete_selected).pack(
                side="left", padx=(8, 0))

        def _refresh_status(self):
            self.show("status")

            def ok(st):
                self._apply_status(st)
                n = len(st.rules)
                self.set_success(
                    f"Firewall is {'active' if st.active else 'inactive'} — "
                    f"{n} rule(s).")
            self._run_async(ufw_mod.status, ok, working="Reading firewall…")

        def _apply_status(self, st):
            self._status = st
            active = bool(st.active)
            self._state_lbl.configure(text="Active" if active else "Inactive")
            self._state_dot.configure(
                text_color=aura.mix(ACCENT, "#0f1115", 0.0) if active
                else aura.mix("#808b9b", "#0f1115", 0.0))
            # green when active, muted-grey when inactive
            self._state_dot.configure(
                text_color=ACCENT if active else "#808b9b")
            self._sync_toggle = True
            try:
                if active:
                    self._toggle.select()
                else:
                    self._toggle.deselect()
            finally:
                self._sync_toggle = False

            def pol(v):
                return v or "—"
            self._defaults_lbl.configure(
                text=f"Default:   incoming {pol(st.default_incoming)}   ·   "
                     f"outgoing {pol(st.default_outgoing)}   ·   "
                     f"routed {pol(st.default_routed)}")
            self._logging_lbl.configure(
                text=f"Logging:   {st.logging}" if st.logging else "")

            for iid in self.tree.get_children():
                self.tree.delete(iid)
            for i, r in enumerate(st.rules):
                self.tree.insert("", "end", iid=str(i), values=(
                    r.number if r.number is not None else "",
                    r.to, r.action, r.frm))

        def _on_toggle(self):
            if self._sync_toggle:
                return
            want = bool(self._toggle.get())
            # optimistic UI is risky for a firewall; run then re-sync from real
            # state.  Revert the visual toggle until the op confirms.
            self._sync_toggle = True
            try:
                (self._toggle.select if not want else self._toggle.deselect)()
            finally:
                self._sync_toggle = False

            def ok(_res):
                self.set_success(
                    f"Firewall {'enabled' if want else 'disabled'}.")
                self._refresh_status()
            self._run_async(lambda: ufw_mod.set_enabled(want), ok,
                            working=f"{'Enabling' if want else 'Disabling'} "
                                    f"firewall…")

        def _delete_selected(self):
            sel = self.tree.selection()
            if not sel or not self._status:
                self.set_status("Select a rule to delete.")
                return
            try:
                rule = self._status.rules[int(sel[0])]
            except (ValueError, IndexError):
                return
            if rule.number is None:
                self.set_error("This rule has no number to delete by.")
                return
            num = rule.number

            def ok(_res):
                self.set_success(f"Deleted rule {num}.")
                self._refresh_status()
            self._run_async(lambda: ufw_mod.delete_rule(num), ok,
                            working=f"Deleting rule {num}…")

        # =================================================================
        # Add rule section
        # =================================================================
        def _build_rules(self, frame):
            presets = aura.Card(frame, title="Quick presets")
            presets.pack(fill="x", pady=(0, 14))
            prow = ctk.CTkFrame(presets.body, fg_color="transparent")
            prow.pack(fill="x")
            for i, (label, _kw) in enumerate(ufw_mod.PRESETS):
                aura.AuraButton(
                    prow, label, kind="secondary", height=32,
                    command=lambda n=label: self._add_preset(n)).pack(
                    side="left", padx=(0 if i == 0 else 8, 0))

            form = aura.Card(frame, title="New rule")
            form.pack(fill="x")

            r1 = ctk.CTkFrame(form.body, fg_color="transparent")
            r1.pack(fill="x", pady=(0, 10))
            aura.Caption(r1, "Action").pack(side="left", padx=(0, 10))
            self._action_seg = aura.SegmentedControl(
                r1, values=["Allow", "Deny", "Reject", "Limit"], width=380)
            self._action_seg.set("Allow")
            self._action_seg.pack(side="left")

            r2 = ctk.CTkFrame(form.body, fg_color="transparent")
            r2.pack(fill="x", pady=(0, 10))
            self._port_entry = aura.AuraEntry(
                r2, placeholder="Port or range — e.g. 22 or 8000:8100",
                width=260)
            self._port_entry.pack(side="left", padx=(0, 10))
            self._proto_var = tk.StringVar(value="tcp")
            self._proto_opt = aura.AuraOption(
                r2, values=["tcp", "udp", "any"], variable=self._proto_var,
                width=110)
            self._proto_opt.pack(side="left")

            r3 = ctk.CTkFrame(form.body, fg_color="transparent")
            r3.pack(fill="x", pady=(0, 4))
            self._from_entry = aura.AuraEntry(
                r3, placeholder="From (optional) — e.g. 192.0.2.0/24")
            self._from_entry.pack(side="left", fill="x", expand=True,
                                  padx=(0, 10))
            self._to_entry = aura.AuraEntry(
                r3, placeholder="To (optional) — address")
            self._to_entry.pack(side="left", fill="x", expand=True)

            self._preview_lbl = aura.Caption(form.body, "")
            self._preview_lbl.pack(anchor="w", pady=(12, 6))
            aura.AuraButton(form.body, "Add rule",
                            command=self._add_from_form).pack(anchor="w")

            for w in (self._port_entry, self._from_entry, self._to_entry):
                w.bind("<KeyRelease>", lambda _e: self._update_preview())
            self._action_seg.configure(command=lambda _v: self._update_preview())
            self._proto_opt.configure(command=lambda _v: self._update_preview())
            self._update_preview()

        def _form_kwargs(self):
            proto = self._proto_var.get()
            return {
                "action": self._action_seg.get().lower(),
                "port": self._port_entry.get().strip() or None,
                "proto": None if proto == "any" else proto,
                "from_addr": self._from_entry.get().strip() or None,
                "to_addr": self._to_entry.get().strip() or None,
            }

        def _update_preview(self):
            try:
                args = ufw_mod.build_rule_args(**self._form_kwargs())
                self._preview_lbl.configure(
                    text="Preview:   ufw " + " ".join(args),
                    text_color=aura.mix(ACCENT, "#808b9b", 0.15))
            except FireGuardError as exc:
                self._preview_lbl.configure(text=str(exc),
                                            text_color="#808b9b")

        def _add_from_form(self):
            try:
                args = ufw_mod.build_rule_args(**self._form_kwargs())
            except FireGuardError as exc:
                self.set_error(str(exc))
                return
            self._add_rule_args(args)

        def _add_preset(self, name):
            try:
                args = ufw_mod.preset_args(name)
            except FireGuardError as exc:
                self.set_error(str(exc))
                return
            self._add_rule_args(args)

        def _add_rule_args(self, args):
            pretty = "ufw " + " ".join(args)

            def ok(_res):
                self.set_success(f"Added: {pretty}")
            self._run_async(lambda: ufw_mod.run_spec(args), ok,
                            working=f"Adding rule ({pretty})…")

        # =================================================================
        # Defaults section
        # =================================================================
        def _build_defaults(self, frame):
            card = aura.Card(frame, title="Default policies")
            card.pack(fill="x")
            aura.Caption(
                card.body,
                "Set the fallback policy applied to traffic that no rule "
                "matches. A locked-down host denies incoming and allows "
                "outgoing.").pack(anchor="w", pady=(0, 12))

            self._default_segs = {}
            for direction in ("incoming", "outgoing", "routed"):
                row = ctk.CTkFrame(card.body, fg_color="transparent")
                row.pack(fill="x", pady=(0, 10))
                aura.Caption(row, direction.capitalize(), width=90,
                             anchor="w").pack(side="left", padx=(0, 12))
                seg = aura.SegmentedControl(
                    row, values=["allow", "deny", "reject"], width=300,
                    command=lambda val, d=direction: self._set_default(d, val))
                seg.pack(side="left")
                self._default_segs[direction] = seg

            self._defaults_hint = aura.Caption(
                card.body, "Press Refresh on the Status page to load the "
                           "current defaults.")
            self._defaults_hint.pack(anchor="w", pady=(6, 0))

        def _set_default(self, direction, policy):
            def ok(_res):
                self.set_success(f"Default {direction} set to {policy}.")
                self._refresh_status()
            self._run_async(lambda: ufw_mod.set_default(direction, policy), ok,
                            working=f"Setting {direction} default to "
                                    f"{policy}…")

        # =================================================================
        # Apps section
        # =================================================================
        def _build_apps(self, frame):
            card = aura.Card(frame, title="Application profiles")
            card.pack(fill="both", expand=True)
            aura.Caption(
                card.body,
                "ufw ships named profiles (from /etc/ufw/applications.d). "
                "Pick one and allow it without remembering ports.").pack(
                anchor="w", pady=(0, 10))
            self._apps_list = tk.Listbox(card.body, height=10,
                                         activestyle="none",
                                         exportselection=False)
            self._apps_list.pack(fill="both", expand=True)
            aura.track(self._apps_list, "listbox")
            btns = ctk.CTkFrame(card.body, fg_color="transparent")
            btns.pack(fill="x", pady=(12, 0))
            aura.AuraButton(btns, "List profiles", kind="secondary",
                            command=self._load_apps).pack(side="left")
            aura.AuraButton(btns, "Allow selected",
                            command=self._allow_selected_app).pack(
                side="left", padx=(8, 0))

        def _load_apps(self):
            def ok(names):
                self._apps_list.delete(0, "end")
                for n in names:
                    self._apps_list.insert("end", n)
                self.set_success(f"{len(names)} application profile(s).")
            self._run_async(ufw_mod.app_list, ok, working="Listing profiles…")

        def _allow_selected_app(self):
            sel = self._apps_list.curselection()
            if not sel:
                self.set_status("Select an application profile first.")
                return
            name = self._apps_list.get(sel[0])

            def ok(_res):
                self.set_success(f"Allowed application profile “{name}”.")
                self._refresh_status()
            self._run_async(lambda: ufw_mod.allow_app(name), ok,
                            working=f"Allowing “{name}”…")

        # =================================================================
        # About section
        # =================================================================
        def _build_about(self, frame):
            card = aura.Card(frame, title="About FireGuard")
            card.pack(fill="x")
            aura.Heading(card.body, APP_NAME).pack(anchor="w")
            aura.Caption(card.body, f"Version {APP_VERSION}").pack(
                anchor="w", pady=(0, 10))
            ctk.CTkLabel(
                card.body, font=aura.font(), justify="left", anchor="w",
                wraplength=560,
                text="A simple, friendly front-end for the Linux Uncomplicated "
                     "Firewall (ufw). See status and rules at a glance, toggle "
                     "the firewall, add or delete rules from a plain form, set "
                     "default policies, and allow application profiles.\n\n"
                     "Privileged changes are applied through pkexec, so no "
                     "terminal is needed. FireGuard never talks to the network "
                     "— it only drives your local ufw.\n\n"
                     "100% AI-built, open source, published on QuickOpen."
                ).pack(anchor="w")
            aura.Caption(card.body,
                         "Licensed under Apache-2.0. Wraps ufw; built on "
                         "CustomTkinter (MIT).").pack(anchor="w", pady=(10, 4))
            aura.AuraButton(card.body, "Project page: quickopen.ai",
                            kind="ghost",
                            command=lambda: open_with_default_app(
                                PROJECT_URL)).pack(anchor="w", pady=(6, 0))

    return App


def main():
    """Entry point: build the root window and run.  Degrades on headless hosts.

    Importing this module does nothing; only this function creates a Tk root.
    With no display (e.g. a server) or without customtkinter installed, it
    prints a friendly note and returns 0 instead of raising.
    """
    try:
        import tkinter as tk
    except Exception as exc:  # tkinter missing entirely
        print(f"{APP_NAME}: a graphical environment with tkinter is required "
              f"to run the GUI ({exc}).")
        return 0

    try:
        App = build_app()
        app = App()
    except ImportError as exc:
        print(f"{APP_NAME}: the GUI needs the 'customtkinter' package "
              f"({exc}). Install it with:  pip install customtkinter")
        return 0
    except tk.TclError as exc:
        print(f"{APP_NAME}: no graphical display available — cannot start the "
              f"GUI here ({exc}). This app is intended for the Linux desktop.")
        return 0
    except Exception as exc:
        print(f"{APP_NAME}: could not start the GUI ({exc}).")
        return 1

    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
