<h3 align="center">SWAG//FIE — Midnight Wireless Testing Framework (Made in 2026)</h3>

<p align="center">
  A single Python+Flask app wrapping the classic Kali wireless audit suite<br>
  in a browser-based console with live output, per-job process control, and<br>
  an authorization gate on every attack module.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SWAG-FIE-purple?style=for-the-badge&logo=wifi&logoColor=white" alt="SwagFie"/>
  <img src="https://img.shields.io/badge/Python-Flask-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Made%20in-2026-purple?style=for-the-badge" alt="2026"/>
</p>

<p align="center">
  <b>Made by</b> Heaven Swag ·
  <a href="https://t.me/he6ca">DM</a>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Commands Reference](#commands-reference)
- [How It Works](#how-it-works)
- [What This Tool Does Not Do](#what-this-tool-does-not-do)
- [Project Structure](#project-structure)
- [Legal Disclaimer](#legal-disclaimer)
- [Contact](#contact)

---

## Overview

**SWAG//FIE** is a single-file Python application that presents the standard Kali wireless audit toolchain — `aircrack-ng`, `hashcat`, `hcxdumptool`, `mdk4`, `hostapd`, `reaver`, `tshark`, and friends — through a midnight-themed web GUI in the browser.

It does not reimplement any wireless logic. Every module is a documented shell command from the upstream tools, executed as-is with your Context tab values substituted in. That means behavior is identical to running the commands by hand — predictable, auditable, debuggable.

The wrapper adds three things the raw tools do not provide:

1. **A unified interface** — every scanner, attack, and defense module in one place instead of three terminal tabs
2. **Live streaming output** — commands stream stdout/stderr line-by-line over Server-Sent Events, not blocked until completion
3. **Per-job process control** — every command runs in its own process group, killable individually or all at once, with no orphaned `aireplay-ng` processes

The authorization gate is real: every attack module requires you to click **"I have written authorization"** in a modal, and the server rejects `POST /api/run` requests with `kind: "attack"` unless they carry `authorized: true`. There is no bypass flag.

---

## Features

- **15 scanner modules** — airodump-ng sweeps, 2.4/5 GHz band scans, PMKID survey, WPS AP scan, hidden SSID reveal, probe/deauth/beacon tshark filters, LAN/service enumeration
- **16 attack modules** — handshake capture, deauth, PMKID capture, WPS Pixie-Dust / PIN brute, evil-twin, mdk4 floods
- **30-point defense checklist** — WPA3-SAE, PMF 802.11w, disable TKIP/WPS/UPnP, min-RSSI, WIDS
- **Live SSE console** — output appears line-by-line as the command runs
- **Per-job process groups** — `os.killpg(os.getpgid(pid), SIGTERM)` on kill, no zombies
- **Honeypot / evil-twin builder** — generates real `hostapd` + `dnsmasq` configs and launches them
- **Authorization gate** — server-side enforcement, not just a UI checkbox
- **DEMO mode auto-detect** — the UI loads anywhere (Android, Windows, macOS, non-root) but streams `[DEMO] Would run: ...` instead of executing; switches to real mode automatically on Kali + root + tools present
- **Portable paths** — no hardcoded `/var/log`; auto-falls back to `~/.swagfie`, Pydroid app-private dir, or `./swagfie_data`
- **Single file** — the entire UI is embedded in `swagfie.py` as one string; no `templates/`, no `static/`, no build step
- **No external runtime** — nothing to compile, nothing to build, just `pip install flask`

---

## Requirements

### Real execution (full functionality)

| Component | Minimum |
|-----------|---------|
| OS | Kali Linux, or Debian/Ubuntu with tools installed |
| Python | 3.8+ |
| Root access | Required — wireless tools need raw socket access |
| Adapter | Monitor-mode capable (Alfa AWUS036ACH, Atheros AR9271, etc.) |
| Internet | Required for tool installation |

### DEMO mode (UI only)

Works on **any** platform with Python 3.8+ and Flask:

- Windows / macOS / Linux (non-root) / Android via Pydroid 3 / Termux
- All buttons validate and fire; the console shows what *would* run

### Required packages

```bash
sudo apt install -y aircrack-ng hashcat hcxdumptool hcxtools mdk4 \
                    reaver bully hostapd hostapd-mana wifiphisher \
                    eaphammer tshark wash
pip install flask
