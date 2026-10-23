<h3 align="center">SWAG//FIE — Midnight Wireless Testing Framework (Made in 2026)</h3>

<p align="center">
  A single Python + Flask application that wraps the classic Kali wireless audit suite<br>
  in a browser-based console with live streaming output, per-job process control,<br>
  an authorization gate on every attack module, and a honeypot/evil-twin builder.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SWAG-FIE-white?style=for-the-badge&logo=wifi&logoColor=black" alt="SwagFie"/>
  <img src="https://img.shields.io/badge/Python-Flask-black?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-white?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Made%20in-2026-black?style=for-the-badge" alt="2026"/>
</p>

<p align="center">
  <b>Made by</b> Heaven Swag ·
  <a href="https://t.me/swghev">Channel</a> ·
  <a href="https://t.me/he6ca">DM</a>
</p>

---

## Table of Contents

- [Overview](#overview)
- [Screenshots](#screenshots)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Commands Reference](#commands-reference)
- [API Reference](#api-reference)
- [How It Works](#how-it-works)
- [What This Tool Does Not Do](#what-this-tool-does-not-do)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [Legal Disclaimer](#legal-disclaimer)
- [Contact](#contact)

---

## Overview

**SWAG//FIE** is a single-file Python application that presents the standard Kali wireless audit toolchain — `aircrack-ng`, `hashcat`, `hcxdumptool`, `mdk4`, `hostapd`, `reaver`, `tshark`, and friends — through a black-and-white web GUI running in your browser.

The tool does **not** reimplement any wireless logic. Every module in the catalog is a documented shell command from the upstream tools, executed as-is with your Context values substituted in. That means behavior is identical to running the command by hand — predictable, auditable, debuggable, and easy to verify against the upstream manuals.

The wrapper adds four things that the raw tools do not provide:

1. **A unified interface** — every scanner, attack, and defense module lives in one place instead of four terminal tabs. You set the interface, BSSID, channel, capture path, and wordlist once, and every module uses them.

2. **Live streaming output** — commands stream stdout and stderr line-by-line over Server-Sent Events, so long-running scans like `airodump-ng` show you what's happening in real time. You don't wait for the command to finish before seeing anything.

3. **Per-job process control** — every running command gets its own process group and job ID. Kill a single scan or all of them at once. No orphaned `aireplay-ng` processes left running after you close the tab.

4. **A real authorization gate** — every attack module requires you to click **"I have written authorization"** in a modal, and the server rejects `POST /api/run` requests with `kind: "attack"` unless they carry `authorized: true`. There is no bypass flag, no `--yolo`, no `--skip-check`. The check runs twice: in the browser and on the server.

The UI is styled after the same aesthetic as VoidPost and VOID//ANON — huge condensed typography, scanline overlay, noise texture, white-on-black monochrome. The giant `SWAG//FIE` masthead is deliberate; you know what tool you're in.

---

## Screenshots

*(Drop a PNG at `docs/screenshot.png` and reference it here. The layout is:
huge `SWAG//FIE` masthead, six tabs (Context / Scanners / Attacks / Protections /
Honeypot / Console), a horizontal context grid at the top, and a streaming console
at the bottom. Everything is monochrome white / grey / black.)*

---

## Features

### Scanners — 15 recon modules

- Full-spectrum `airodump-ng` sweep
- 2.4 GHz band scan (channels 1–14)
- 5 GHz band scan
- Targeted AP + client capture with BSSID filter and channel hop
- Hidden SSID reveal (CSV output mode)
- WPS AP scan via `wash`
- PMKID-capable AP survey via `hcxdumptool --do_rcascan`
- Probe-request logger (`tshark` filter on subtype 4)
- Deauth-frame detector (`tshark` filter on subtype 12)
- Beacon flood detector (deduplicated SSID counting)
- Handshake presence check via `aircrack-ng -b`
- PCAP → hashcat 22000 conversion via `hcxpcapngtool`
- LAN host discovery via `nmap -sn`
- LAN service enumeration via `nmap -sV`
- ARP scan via `arp-scan`

### Attacks — 16 offensive modules

- Enable monitor mode (`airmon-ng check kill` + `airmon-ng start`)
- Capture WPA handshake
- Deauth a single client (5 frames) or broadcast (continuous)
- PMKID capture (clientless)
- PMKID → hashcat 22000 conversion
- Crack via `aircrack-ng` (CPU) or `hashcat` (GPU/CPU)
- Crack with best64 rules, or mask attack
- WPS Pixie-Dust attack via `reaver -K 1`
- WPS PIN brute via `reaver -N`
- Evil-twin AP via `hostapd`
- Beacon flood, auth flood, deauth amok, EAPOL flood via `mdk4`

### Protections — 30-point defense checklist

A hardening guide for your own access point. Everything from "enforce WPA3-SAE only" down to "quarterly authorized pentest of your own WLAN". Plus a one-click PSK generator using `secrets.token_urlsafe(18)`.

### Honeypot / Evil-Twin builder

Launch a real `hostapd` honeypot that logs probe requests and auth frames via `tshark`, or an evil-twin with `dnsmasq` for DNS redirection. The config files are generated on the fly and written to `/tmp`.

### The wrapper mechanics

- Live Server-Sent Events (SSE) streaming of every command's stdout/stderr
- Per-job process groups (`os.killpg(os.getpgid(pid), SIGTERM)`) — no zombies
- Server-side validation of BSSID format, channel range, capture file, and wordlist before any command runs
- DEMO mode auto-detection: the UI loads anywhere, but only executes on Kali + root + tools present
- Portable paths: no hardcoded `/var/log`, auto-falls back to `~/.swagfie`, Pydroid app-private dir, or `./swagfie_data`
- Single file: the entire UI is embedded in `swagfie.py` as one string — no `templates/`, no `static/`, no build step
- Zero JavaScript dependencies — plain DOM manipulation, no React/Vue/jQuery

---

## Requirements

### Real execution (full functionality)

| Component | Minimum |
|-----------|---------|
| OS | Kali Linux, or Debian/Ubuntu with tools installed |
| Python | 3.8+ |
| Root access | Required — wireless tools need raw socket access |
| Adapter | Monitor-mode capable (Alfa AWUS036ACH, Atheros AR9271, RTL8812AU, etc.) |
| Internet | Required for tool installation |

Common monitor-mode adapters:

| Adapter | Chipset | 2.4 GHz | 5 GHz | Notes |
|---------|---------|---------|-------|-------|
| Alfa AWUS036ACH | RTL8812AU | ✅ | ✅ | Best value, needs `rtl8812au-dkms` |
| Alfa AWUS036NHA | AR9271 | ✅ | ❌ | Plug-and-play on Kali |
| Alfa AWUS1900 | RTL8814AU | ✅ | ✅ | Higher power |
| Panda PAU09 | RT5572 | ✅ | ✅ | Compact |
| TP-Link TL-WN722N v1 | AR9271 | ✅ | ❌ | **v1 only** — v2/v3 use unsupported chipsets |

### DEMO mode (UI only)

Works on **any** platform with Python 3.8+ and Flask:

- Windows / macOS / Linux (non-root) / Android via Pydroid 3 / Termux
- All buttons validate and fire; the console shows `[DEMO] Would run: <cmd>` instead of executing
- Useful for previewing the UI, developing new modules, or teaching the workflow

### Required packages

```bash
sudo apt install -y aircrack-ng hashcat hcxdumptool hcxtools mdk4 \
                    reaver bully hostapd hostapd-mana wifiphisher \
                    eaphammer tshark wash
pip install flask
