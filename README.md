<div align="center">

```
██████╗ ██╗██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗███╗  ██╗███████╗██████╗
██╔══██╗██║╚██╗██╔╝    ██╔════╝██╔════╝██╔══██╗████╗ ██║████╗ ██║██╔════╝██╔══██╗
██████╔╝██║ ╚███╔╝     ███████╗██║     ███████║██╔██╗██║██╔██╗██║█████╗  ██████╔╝
██╔══██╗██║ ██╔██╗     ╚════██║██║     ██╔══██║██║╚████║██║╚████║██╔══╝  ██╔══██╗
██║  ██║██║██╔╝╚██╗    ███████║╚██████╗██║  ██║██║ ╚███║██║ ╚███║███████╗██║  ██║
╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝
```

# ⚡ RIX SCANNER v11.0

**Ultimate CDN Clean IP Scanner — Real TLS/SNI | IPv4 + IPv6 | Zero Fake Tests**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-Personal%20Use-orange?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-11.0-brightgreen?style=for-the-badge)](https://github.com/t54245448-a11y/RIX-SCANNER)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Android%20%7C%20Windows%20%7C%20macOS-purple?style=for-the-badge)](https://github.com/t54245448-a11y/RIX-SCANNER)
[![IPv6](https://img.shields.io/badge/IPv6-Supported-cyan?style=for-the-badge)](https://github.com/t54245448-a11y/RIX-SCANNER)
[![No Deps](https://img.shields.io/badge/Dependencies-Zero%20(stdlib%20only)-success?style=for-the-badge)](https://github.com/t54245448-a11y/RIX-SCANNER)

---

> 🔍 **RIX SCANNER** finds the fastest clean Cloudflare CDN IPs from your network using **real TCP+TLS connections** — no simulation, no fake ping, no mock data. Every latency measurement comes from an actual network round-trip.

</div>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🔬 How It Works](#-how-it-works)
- [⚡ Quick Start](#-quick-start)
- [🚀 Installation](#-installation)
  - [🐧 Linux / VPS Server](#-linux--vps-server)
  - [📱 Termux (Android)](#-termux-android)
  - [🪟 Windows](#-windows)
  - [🍎 macOS](#-macos)
- [📱 Pydroid3 (Android)](#-pydroid3-android)
- [🗺️ Menu & Commands](#️-menu--commands)
- [🌐 IP Version Support](#-ip-version-support)
- [🇮🇷 NET-MELI Mode](#-net-meli-mode)
- [🌍 Multi-CDN Scan](#-multi-cdn-scan)
- [🔌 Port Scanner](#-port-scanner)
- [📤 Export Formats](#-export-formats)
- [🔄 Auto Scheduler](#-auto-scheduler)
- [⚙️ Technical Details](#️-technical-details)
- [🗂️ Output Files](#️-output-files)
- [❓ FAQ](#-faq)
- [📜 Changelog](#-changelog)

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔥 Core Scanner
- ✅ **Real TCP + TLS handshake** — not ping
- ✅ **CIDR-based detection** — primary confirmation
- ✅ **CF header fingerprinting** — bonus check
- ✅ **TCP pre-filter** — eliminates dead IPs at 3× speed
- ✅ **Retry logic** — 2 attempts on timeout/unreachable
- ✅ **Parallel scanning** — up to 200 threads
- ✅ **Auto thread scaling** — based on IP count
- ✅ **Live ETA & stats** — every 100 IPs

### 🌐 IPv4 + IPv6
- ✅ **15 CF CIDRs** (IPv4, ASN 13335)
- ✅ **13 CF CIDRs** (IPv6, ASN 13335)
- ✅ **IPv6 auto-detect** — graceful fallback
- ✅ **IPv6 in all CDN providers**
- ✅ **Mixed mode** — scan both simultaneously

</td>
<td width="50%">

### 🇮🇷 Iran Optimized
- ✅ **NET-MELI mode** — ISP-aware scanning
- ✅ **13 Iranian ISPs** — MCI, Irancell, Rightel, Shatel...
- ✅ **Fast-edge subnets** — best CF nodes for Iran
- ✅ **VPN detection** — warns before scan
- ✅ **GeoIP check** — confirms Iranian IP

### 📦 All-in-One
- ✅ **Multi-CDN** — Fastly, Gcore, Bunny, KeyCDN, CDN77, Sucuri, StackPath
- ✅ **Port scanner** — real TCP, no ICMP
- ✅ **Speed test** — real 100KB download benchmark
- ✅ **Auto scheduler** — repeat scan on interval
- ✅ **Scan history** — last 10 sessions
- ✅ **4 export formats** — TXT, JSON, CSV, v2ray
- ✅ **Dual language** — English / فارسی
- ✅ **Background CIDR update** — every 6 hours

</td>
</tr>
</table>

---

## 🔬 How It Works

RIX SCANNER uses a **3-step pipeline** to find clean Cloudflare IPs:

```
Step 1: IP Generation (Ultra-fast)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Pre-computed CIDR tuples → Weighted random selection
  IPv4: ~2ms per 1,000 IPs
  IPv6: ~8ms per 1,000 IPs

Step 2: TCP Pre-filter (3× thread count)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Fast TCP connect on port 443 (1.5s timeout)
  Eliminates ~60-70% dead IPs upfront
  Only alive IPs pass to Step 3

Step 3: Real TLS Test (Zero Fake)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ① Raw TCP socket connect     → tcp_ms
  ② TLS 1.2+ handshake + SNI  → tls_ms
  ③ HTTP HEAD request          → response
  ④ Parse CF markers           → confirm
  ⑤ CIDR membership check      → validate
  ⑥ Total latency              → tcp+tls+http
```

### Detection Logic (CIDR-based — fixes false positives)

```python
# PRIMARY: IP in CF CIDR + TLS success + HTTP response = CONFIRMED CLEAN
# This is reliable even when cf-ray headers are absent (restricted networks)

if (ip_in_cf_cidr AND got_http_response):
    status = "CLEAN"  # CIDR confirmed
elif (cf_strong_headers AND got_http):
    status = "CLEAN"  # Header confirmed
```

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/t54245448-a11y/RIX-SCANNER.git
cd RIX-SCANNER

# Run (no installation required)
python3 rix_scanner.py
```

> **Zero dependencies** — uses only Python standard library (`socket`, `ssl`, `ipaddress`, `threading`, `json`)

---

## 🚀 Installation

### 🐧 Linux / VPS Server

**Ubuntu / Debian:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python 3 (if not installed)
sudo apt install -y python3 python3-pip git

# Clone RIX SCANNER
git clone https://github.com/t54245448-a11y/RIX-SCANNER.git
cd RIX-SCANNER

# Make executable
chmod +x rix_scanner.py

# Run
python3 rix_scanner.py
```

**CentOS / RHEL / AlmaLinux:**
```bash
sudo dnf install -y python3 git
git clone https://github.com/t54245448-a11y/RIX-SCANNER.git
cd RIX-SCANNER
python3 rix_scanner.py
```

**Run in background (keep running after SSH disconnect):**
```bash
# Using screen
sudo apt install -y screen
screen -S rix
python3 rix_scanner.py
# Detach: Ctrl+A then D
# Reattach: screen -r rix

# Or using tmux
sudo apt install -y tmux
tmux new -s rix
python3 rix_scanner.py
# Detach: Ctrl+B then D
# Reattach: tmux attach -t rix

# Or using nohup
nohup python3 rix_scanner.py > rix_output.log 2>&1 &
tail -f rix_output.log
```

**Check IPv6 support on server:**
```bash
# Check if IPv6 is enabled
ip -6 addr show
ping6 2606:4700:4700::1111

# Enable IPv6 if disabled (Ubuntu)
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=0
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=0
```

---

### 📱 Termux (Android)

> RIX SCANNER runs perfectly on Termux — no root required!

```bash
# Step 1: Install Termux from F-Droid (recommended) or Play Store
# https://f-droid.org/packages/com.termux/

# Step 2: Update packages
pkg update && pkg upgrade -y

# Step 3: Install Python and Git
pkg install python git -y

# Step 4: Clone RIX SCANNER
git clone https://github.com/t54245448-a11y/RIX-SCANNER.git
cd RIX-SCANNER

# Step 5: Run
python rix_scanner.py
```

**Termux Tips:**
```bash
# Keep Termux running in background
# Install Termux:Boot from F-Droid for auto-start

# Give storage permission (to save to Downloads)
termux-setup-storage
# Then files will save to: /sdcard/Download/RIX-CLEAN.txt

# Check IPv6 on your phone
ip -6 addr show
# If IPv6 is available, choose option 2 or 3 in the scanner

# Run with larger screen (optional)
pkg install tmux -y
tmux new -s rix
python rix_scanner.py

# For faster scanning on phone, use Quick Scan (option 2)
# Recommended: 100-300 IPs, max 200ms latency
```

**Termux Shortcut (create alias):**
```bash
echo "alias rix='cd ~/RIX-SCANNER && python rix_scanner.py'" >> ~/.bashrc
source ~/.bashrc
# Now just type: rix
```

---

### 🪟 Windows

```powershell
# Step 1: Install Python from https://python.org
# Make sure to check "Add Python to PATH" during installation

# Step 2: Open Command Prompt or PowerShell

# Step 3: Install Git (optional)
# Download from https://git-scm.com

# Step 4: Clone or download
git clone https://github.com/t54245448-a11y/RIX-SCANNER.git
cd RIX-SCANNER

# Step 5: Run
python rix_scanner.py
```

**Windows without Git:**
1. Go to [github.com/t54245448-a11y/RIX-SCANNER](https://github.com/t54245448-a11y/RIX-SCANNER)
2. Click **Code** → **Download ZIP**
3. Extract the ZIP
4. Open Command Prompt in the folder
5. Run: `python rix_scanner.py`

**Windows batch file (double-click to run):**
```batch
@echo off
cd /d "%~dp0"
python rix_scanner.py
pause
```
Save as `RUN_RIX.bat` in the same folder.

---

### 🍎 macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3 git

# Clone
git clone https://github.com/t54245448-a11y/RIX-SCANNER.git
cd RIX-SCANNER

# Run
python3 rix_scanner.py
```

---

## 📱 Pydroid3 (Android)

> For users who prefer a GUI Python IDE on Android

```
1. Install Pydroid3 from Google Play Store
2. Open Pydroid3
3. Download rix_scanner.py to your device
4. Open the file in Pydroid3
5. Tap the Run button (▶)

Output file: /data/user/0/ru.iiec.pydroid3/files/RIX-CLEAN.txt
```

> **Note:** For Termux, files save to `/sdcard/Download/RIX-CLEAN.txt` which is accessible from your file manager.

---

## 🗺️ Menu & Commands

When you run RIX SCANNER, you'll see this menu:

```
╔══════════════════════════════════════════════════════╗
║ ◆ RIX SCANNER — MAIN MENU                           ║
╠══════════════════════════════════════════════════════╣
║  1  Start Scan          [full config]                ║
║  2  Quick Scan          [AI-preset, 2Q]              ║
║  3  NET-MELI            [Iran ISP optimized]         ║
║  4  Multi-CDN           [Fastly/Gcore/Bunny+]        ║
║  5  Port Scanner        [real TCP]                   ║
║  6  History             [last 10]                    ║
║  7  Export              [TXT/JSON/CSV/v2ray]         ║
║  8  Speed Test          [real download]              ║
║  9  Auto Scheduler      [repeat scan]                ║
║  A  Update CIDRs        [Cloudflare API]             ║
║  L  Language            [EN/FA]                      ║
║  0  Exit                                             ║
╚══════════════════════════════════════════════════════╝
```

| Option | Description | Best For |
|--------|-------------|----------|
| **1** Start Scan | Full manual config — mode, IPv4/6, count, latency, SNI, timeout | Power users |
| **2** Quick Scan | AI preset — just enter count & max latency | Beginners, fast results |
| **3** NET-MELI | Auto-detects your Iranian ISP, optimizes CIDRs | Iran users |
| **4** Multi-CDN | Scans Fastly, Gcore, Bunny, KeyCDN, CDN77, Sucuri, StackPath | Non-CF CDNs |
| **5** Port Scanner | Real TCP port check on any IP | Network diagnostics |
| **6** History | View last 10 scan sessions | Track progress |
| **7** Export | Save results in TXT/JSON/CSV/v2ray format | Share/use results |
| **8** Speed Test | Real 100KB download from clean IPs | Find fastest IP |
| **9** Scheduler | Auto-repeat scan every N minutes | Automation |
| **A** Update CIDRs | Fetch latest ranges from Cloudflare API | Keep data fresh |
| **L** Language | Switch English ↔ فارسی | Interface language |

---

## 🌐 IP Version Support

RIX SCANNER fully supports IPv4, IPv6, and mixed scanning:

```
IP Version Selection
━━━━━━━━━━━━━━━━━━━
1. IPv4 only     → Always works
2. IPv6 only     → Requires IPv6-enabled network
3. Both          → Scans both, best coverage
```

### Cloudflare IPv4 Ranges (ASN 13335)
```
103.21.244.0/22    103.22.200.0/22    103.31.4.0/22
104.16.0.0/13      104.24.0.0/14      108.162.192.0/18
131.0.72.0/22      141.101.64.0/18    162.158.0.0/15
172.64.0.0/13      173.245.48.0/20    188.114.96.0/20
190.93.240.0/20    197.234.240.0/22   198.41.128.0/17
```
*Total: 15 CIDRs | ~1.2 million IPs*

### Cloudflare IPv6 Ranges (ASN 13335)
```
2606:4700::/32          2606:4700:3000::/48    2606:4700:3001::/48
2606:4700:3002::/48     2606:4700:3003::/48    2606:4700:3004::/48
2606:4700:3005::/48     2606:4700:3006::/48    2606:4700:3007::/48
2400:cb00::/32          2803:f800::/32          2c0f:f248::/32
2a06:98c0::/29
```
*Total: 13 CIDRs | Trillions of IPs*

> **IPv6 Auto-detect:** RIX SCANNER automatically checks if your system supports IPv6 before allowing IPv6 scanning. If not available, it falls back to IPv4.

---

## 🇮🇷 NET-MELI Mode

NET-MELI is an Iran-optimized scan mode that:

1. **Auto-detects your ISP** from GeoIP + ASN
2. **Selects best CF subnets** for your specific ISP
3. **Combines fast-edge IPs** with ISP-matched CIDRs
4. **Removes VPN interference** before scanning

### Supported Iranian ISPs

| ISP | ASN | Supported |
|-----|-----|-----------|
| MCI / Hamrah Aval | AS44244 | ✅ |
| Irancell MTN | AS197207 | ✅ |
| Rightel | AS57218 | ✅ |
| Shatel | AS31549 | ✅ |
| Asiatech | AS25184 | ✅ |
| Pars Online | AS16322 | ✅ |
| Respina | AS48159 | ✅ |
| TCI ADSL | AS48147 | ✅ |
| Afranet / Fanava | — | ✅ |
| Mobinnet | AS50810 | ✅ |
| Ziatel | AS49100 | ✅ |
| Neda | AS12880 | ✅ |
| Sabanet / DD3 | — | ✅ |

### Fast-Edge Subnets for Iran (IPv4)
```
104.16.0.0/13    104.24.0.0/14    172.64.0.0/13
162.158.0.0/15   188.114.96.0/20  190.93.240.0/20
```

### Fast-Edge Subnets for Iran (IPv6)
```
2606:4700::/32   2606:4700:3000::/48   2606:4700:3001::/48
```

---

## 🌍 Multi-CDN Scan

Scan CDN providers beyond Cloudflare:

| Provider | IPv4 CIDRs | IPv6 CIDRs |
|----------|-----------|-----------|
| **Fastly** | 4 ranges | 3 ranges |
| **Gcore** | 3 ranges | 2 ranges |
| **Bunny CDN** | 2 ranges | 1 range |
| **KeyCDN** | 2 ranges | 1 range |
| **CDN77** | 2 ranges | 1 range |
| **Sucuri** | 2 ranges | 1 range |
| **StackPath** | 2 ranges | 1 range |

> **Note:** Multi-CDN mode uses TLS+HTTP detection (no CIDR check) since these are not Cloudflare IPs.

---

## 🔌 Port Scanner

Real TCP connect test — zero simulation:

```
Port Sets Available:
━━━━━━━━━━━━━━━━━━━
1. CF Ports     → 80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096
2. Common Ports → SSH, FTP, SMTP, DNS, HTTP, HTTPS, MySQL, Redis, MongoDB...
3. Custom Range → Define your own start–end port range
```

| Port | Service | Cloudflare |
|------|---------|-----------|
| 80 | HTTP | ✅ |
| 443 | HTTPS | ✅ |
| 2052 | CF-Alt | ✅ |
| 2053 | CF-TLS | ✅ |
| 2082 | CF-Alt2 | ✅ |
| 2083 | CF-TLS2 | ✅ |
| 2086 | CF-Alt3 | ✅ |
| 2087 | CF-TLS3 | ✅ |
| 2095 | CF-Alt4 | ✅ |
| 2096 | CF-TLS4 | ✅ |

---

## 📤 Export Formats

After scanning, export your clean IPs in multiple formats:

### 1. TXT — Plain IP List (`RIX-CLEAN.txt`)
```
104.16.45.2
172.67.189.11
188.114.97.3
2606:4700::6810:2d02
```
*One IP per line. No comments. No headers. Ready for v2ray/xray/sing-box.*

### 2. JSON (`rix_export.json`)
```json
{
  "generated": "2025-01-15T14:30:00",
  "count": 25,
  "ips": [
    {"ip": "104.16.45.2", "latency_ms": 48.3, "sni": "speed.cloudflare.com", "ipv": "4"},
    {"ip": "2606:4700::1", "latency_ms": 63.1, "sni": "speed.cloudflare.com", "ipv": "6"}
  ]
}
```

### 3. CSV (`rix_export.csv`)
```csv
ip,latency_ms,sni,ipv
104.16.45.2,48.3,speed.cloudflare.com,4
172.67.189.11,63.1,speed.cloudflare.com,4
2606:4700::1,71.2,speed.cloudflare.com,6
```

### 4. v2ray Format (`rix_v2ray.txt`)
```
# RIX Clean IPs — 2025-01-15 14:30
104.16.45.2  # 48ms  sni=speed.cloudflare.com  IPv4
172.67.189.11  # 63ms  sni=speed.cloudflare.com  IPv4
2606:4700::1  # 71ms  sni=speed.cloudflare.com  IPv6
```

### Save Locations

| Platform | Path |
|----------|------|
| Android (Termux) | `/sdcard/Download/RIX-CLEAN.txt` |
| Android (Pydroid3) | `/data/user/0/ru.iiec.pydroid3/files/RIX-CLEAN.txt` |
| Windows | `C:\Users\<user>\Downloads\RIX-CLEAN.txt` |
| Linux / macOS | `~/Downloads/RIX-CLEAN.txt` |

---

## 🔄 Auto Scheduler

Set RIX SCANNER to run automatically at intervals:

```
Configuration:
━━━━━━━━━━━━━
IPs per scan     : 300 (recommended)
Max latency (ms) : 200
Interval (min)   : 30
Repeat count     : 3 (or 0 for infinite)
```

- Results overwrite `RIX-CLEAN.txt` each run
- History is saved after each run
- Press `Ctrl+C` to stop the scheduler

---

## ⚙️ Technical Details

### Generation Algorithm
```python
# Pre-computed CIDR tuples for O(1) random IP generation
# (base_int, size, version) — no repeated network parsing
# Weighted random: larger CIDRs get proportionally more IPs
# Speed: ~2ms per 1,000 IPv4 | ~8ms per 1,000 IPv6
```

### CIDR Checker — O(1) Per IP
```python
# CidrSet uses pre-computed (network_int & mask_int) pairs
# contains(ip): any((ip_int & mask) == network)
# No repeated ipaddress.ip_network() calls during scan
```

### TLS Test Pipeline
```
TCP connect   →  tcp_ms
TLS handshake →  tls_ms (TLS 1.2 minimum, SNI enabled)
HTTP HEAD     →  "HEAD / HTTP/1.1\r\nHost:{sni}\r\n..."
Response read →  max 6144 bytes
CF detection  →  CIDR check + cf-ray + cf-cache-status + nel: + report-to:
Total latency →  tcp + tls + http round-trip (real end-to-end)
```

### Thread Configuration
```
TCP pre-filter threads : min(500, scan_threads × 3)
Scan threads           : min(200, max(50, ip_count ÷ 5))
Background CIDR update : every 6 hours (daemon thread)
IPv6 check             : background thread at startup
```

### SNI Options
```
1. cloudflare.com
2. speed.cloudflare.com  ← Fastest, recommended
3. one.one.one.one
4. www.cloudflare.com
5. blog.cloudflare.com
6. developers.cloudflare.com
7. dash.cloudflare.com
0. Custom (enter your own)
```

---

## 🗂️ Output Files

| File | Location | Description |
|------|----------|-------------|
| `RIX-CLEAN.txt` | Downloads folder | Plain IP list — main output |
| `rix_export.json` | Downloads folder | JSON with latency + SNI + IPv |
| `rix_export.csv` | Downloads folder | Spreadsheet format |
| `rix_v2ray.txt` | Downloads folder | v2ray-ready with comments |
| `rix_history.json` | Script folder | Last 10 scan sessions |

> **Important:** `RIX-CLEAN.txt` is **always overwritten** — never creates duplicate files.

---

## ❓ FAQ

<details>
<summary><b>Q: Why are my scanned IPs not working in v2ray/xray?</b></summary>

Make sure you're using IPs from `RIX-CLEAN.txt` (status = CLEAN, confirmed by CIDR). Also verify:
- VPN was OFF during scan
- You're on an Iranian network
- The SNI matches your config's host header
- Try `speed.cloudflare.com` as SNI for best results

</details>

<details>
<summary><b>Q: VPN is ON — should I disable it?</b></summary>

Yes. Running the scanner with VPN active causes:
- Wrong latency measurements (routed through VPN server)
- False positives — IPs fast from VPN but slow from Iran
- Incorrect CIDR matching

Always disable VPN before scanning, then re-enable after.

</details>

<details>
<summary><b>Q: IPv6 option is grayed out — why?</b></summary>

Your network or device doesn't support IPv6 outbound connections. This is common on:
- VPS servers without IPv6 routing configured
- Mobile networks that don't assign IPv6
- Some ISPs in Iran

Use IPv4 mode (option 1) — it works everywhere.

</details>

<details>
<summary><b>Q: How many IPs should I scan?</b></summary>

| Use Case | Recommended Count | Max Latency |
|----------|------------------|-------------|
| Quick check | 100–200 | 150ms |
| Daily use | 300–500 | 200ms |
| Full scan | 1,000–2,000 | 300ms |
| Server (VPS) | 5,000+ | 500ms |

</details>

<details>
<summary><b>Q: What's the difference between Quick Scan and Full Scan?</b></summary>

**Quick Scan (option 2):**
- AI-preset: Iran-Optimized mode, `speed.cloudflare.com` SNI, 3.0s timeout
- Only 2 questions: IP count + max latency
- Best for: fast results, beginners

**Full Scan (option 1):**
- Manual control: mode, IPv version, count, latency, timeout, delay, SNI
- All parameters customizable
- Best for: power users, specific requirements

</details>

<details>
<summary><b>Q: What does NET-MELI mode do differently?</b></summary>

NET-MELI detects your Iranian ISP (MCI, Irancell, etc.) and:
1. Prioritizes CF subnets known to be fast for your ISP
2. Mixes fast-edge IPs with ISP-specific CIDRs
3. Uses 0 delay and 3.5s timeout for speed
4. Default count: 800 IPs (more = better results)

</details>

<details>
<summary><b>Q: Can I run this on a cheap VPS?</b></summary>

Yes! Minimum requirements:
- 256MB RAM
- 1 CPU core
- Python 3.8+
- Any Linux distribution

For VPS, use 50–100 threads max to avoid network errors. The scanner auto-scales based on IP count.

</details>

<details>
<summary><b>Q: How often should I update CIDRs?</b></summary>

CIDRs auto-update every 6 hours in the background. The banner shows `[LIVE@HH:MM]` when live data is loaded. You can also manually update with option **A**.

Cloudflare rarely changes their IP ranges, so the built-in list is usually sufficient.

</details>

---

## 📜 Changelog

### v11.0 — RIX SCANNER (Current)
- 🆕 **Renamed** to RIX SCANNER with new ASCII art
- 🆕 **IPv6 full support** — all CDN providers now have IPv6 ranges
- 🆕 **13 CF IPv6 CIDRs** — complete coverage
- ⚡ **Ultra-fast generation** — pre-computed CIDR tuples (~2ms/1000 IPs)
- ⚡ **O(1) CIDR checker** — `CidrSet` class with bitmask operations
- ⚡ **TCP pre-filter at 3×** — min(500, threads×3) for faster dead-IP removal
- 🎨 **New orange/purple color scheme** with ◆ decorators
- 🔧 **Bug fix** — Pars AS16322 ISP detection corrected
- 🔧 **Bug fix** — Multi-CDN v6 CIDRs for all 7 providers
- 🌐 **Multi-CDN IPv6** — Fastly, Gcore, Bunny, KeyCDN, CDN77, Sucuri, StackPath
- 📊 **History** now tracks IPv4 vs IPv6 clean IP counts separately

### v10.0
- IPv4+IPv6 dual stack support
- Pre-computed IP generation
- Background CIDR auto-updater
- Upgraded ASCII art with box-drawing characters

### v9.0.0
- CIDR-based detection (fixes false positives)
- TCP pre-filter for 3× speed boost
- NET-MELI mode with 13 Iran ISPs
- Multi-CDN scan (7 providers)
- Port scanner with real TCP
- Speed test with real download
- Auto scheduler
- History tracking
- 4 export formats
- Dual language EN/FA

---

## 📄 License

```
RIX SCANNER — Personal Use Only

This tool is designed for personal network optimization.
All scanned IPs are publicly routed Cloudflare addresses.
Use responsibly and in compliance with your local laws.
```

---

<div align="center">

**Made with ⚡ for better connectivity**

[![GitHub](https://img.shields.io/badge/GitHub-t54245448--a11y%2FRIX--SCANNER-181717?style=for-the-badge&logo=github)](https://github.com/t54245448-a11y/RIX-SCANNER)

*RIX SCANNER v11.0 — Zero fake tests. Real results.*

</div>
