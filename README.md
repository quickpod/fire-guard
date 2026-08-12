# FireGuard

A simple, friendly, **100% open-source** GUI for the Linux **ufw** firewall. See your firewall at a glance and manage it without the command line. Built entirely by AI with human testing and guidance, and published on [QuickOpen](https://quickopen.ai/projects/fire-guard).

> **100% AI-built and open source.** Apache-2.0.

## What it does

FireGuard is a friendly front-end for the Uncomplicated Firewall (`ufw`). It shows whether the firewall is active, the default incoming/outgoing/routed policies, and the numbered rule list — then lets you change any of it from a plain window: toggle the firewall, add or delete rules, set default policies, and allow application profiles. Every privileged change is applied through **pkexec**, so no terminal is needed. Nothing ever touches the network — FireGuard only drives your local `ufw`.

## Install

Download the release from the [QuickOpen page](https://quickopen.ai/projects/fire-guard) or the [GitHub release](https://github.com/quickpod/fire-guard/releases/latest). FireGuard manages `ufw`, so it runs on Linux; make sure `ufw` is installed (`sudo apt install ufw`).

## Run from source

```sh
pip install -r requirements.txt
python fire_guard_app.py            # GUI
python -m fireguard --help          # CLI
```

## Features

- **Status at a glance.** Active/inactive, default in/out/routed policies,
  logging level, and the full **numbered** rule list — parsed from
  `ufw status verbose` + `ufw status numbered` in a single elevated call.
- **One-flip toggle.** Enable or disable the firewall with a switch.
- **Friendly rule form.** Allow / Deny / Reject / Limit, a port or range, a
  protocol (tcp/udp), and optional from/to addresses — with a live preview of
  the exact `ufw` command. One-click presets: **Allow SSH / HTTP / HTTPS**.
- **Delete by number.** Select a rule and remove it (`ufw --force delete N`).
- **Default policies.** Set incoming / outgoing / routed to allow, deny or
  reject.
- **Application profiles.** List `ufw app list` and allow a profile by name.
- **No terminal required.** Privileged operations run via **pkexec** (falling
  back to `sudo -n`), so the GUI applies changes without a shell.
- **Safe everywhere.** The parsers and the rule-spec builder are pure Python;
  the app imports and runs on any OS, and on a box without `ufw` it degrades
  with a clear "ufw not available" message instead of crashing.

## CLI examples

```sh
# Show status, defaults and the numbered rule list
python -m fireguard status

# Turn the firewall on / off
python -m fireguard enable
python -m fireguard disable

# Allow / deny — a raw ufw spec, or friendly flags
python -m fireguard allow 22/tcp
python -m fireguard allow --port 443 --proto tcp
python -m fireguard deny  --port 3306 --from 192.0.2.0/24

# Delete rule number 3 (see 'status')
python -m fireguard delete 3

# Default policies
python -m fireguard default incoming deny
python -m fireguard default outgoing allow

# Application profiles
python -m fireguard apps
python -m fireguard apps --allow OpenSSH
```

## How privileged operations work

Reading and changing `ufw` requires root. FireGuard never asks you to run it as
root: each privileged call is prefixed with **`pkexec`** (which pops the
graphical polkit authorization dialog), falling back to non-interactive
`sudo -n` if pkexec is unavailable, or nothing when already root. Status reads
run verbose + numbered under one authorization prompt. `--force` is used for
`enable`/`disable`/`delete` so the GUI is never left waiting on a hidden
terminal confirmation.

## License

Apache-2.0 — see [LICENSE](LICENSE). A 100% AI-built project published on QuickOpen.
