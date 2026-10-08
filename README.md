<p align="center">
  <img src="assets/icon.png" width="140" alt="Auto IP Changer icon"/>
</p>

<h1 align="center">Auto IP Changer 🧅🔄</h1>

<p align="center">
  <strong>A Windows system-tray app that rotates your public IP through Tor on your schedule — and guarantees every new IP was never used before.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%2B-0078D6?logo=windows11&logoColor=white" alt="Windows"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Tor-0.4.8%20Expert%20Bundle-7E4798?logo=tor&logoColor=white" alt="Tor"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"/>
  <img src="https://img.shields.io/badge/UI-system%20tray%20%2B%20toasts-4ECDC4" alt="Tray app"/>
</p>

---

## ✨ What it does

- **Rotates your exit IP automatically** every X minutes (default 30, your choice from the tray menu).
- **Shows your IP + country in real time** 🌍: the tray tooltip reads `Auto IP Changer v1.1.0 - IP 185.220.101.15 (Sweden) - next change in 12:34`, and the menu shows `Current IP: ... (country)` — country comes from live geo lookup of every exit IP.
- **Never reuses an IP.** Every new exit IP is verified live and checked against a persistent history file — if Tor offers one you've had before, it rotates again until it gets a genuinely new one.
- **Lives in your system tray.** No terminal windows, ever. The icon shows a purple onion with a rotation arrow, and hovering it displays:
  ```
  Auto IP Changer - IP 185.220.101.15 - next change in 12:34
  ```
- **Tells you everything**: toast notifications on every IP change, `current_ip.txt` always holds the current IP, and `ip_log.txt` keeps a timestamped history of every rotation.
- **Always starts disabled** 🛑: every launch begins safely on your **default IP** (Tor not running), no matter what the settings say — rotation only runs after you explicitly click *Enable IP rotation* in the tray menu.
- **One-click Disable** 🛑: right-click → *Disable (use my default IP)* stops rotation, shuts Tor down, and shows your **default public IP** in the tooltip, tray menu and `current_ip.txt` for as long as it's off. *Enable IP rotation* brings everything back with a fresh never-used IP.
- **Fails fast, self-heals**: short timeouts everywhere, verifies Tor's actual control-port replies, kills and restarts Tor if it stops working, retries failed cycles within seconds — the main loop cannot die.
- **Fights for your privacy baseline**: SOCKS5 on `127.0.0.1:9050`, ControlPort on `127.0.0.1:9051` — local only.

## ⬇️ Download the ready-made exe

Grab **`AutoIpChanger.exe`** from the [**Releases**](https://github.com/Michaelunkai/tor-ip-rotator/releases/latest) page — no build needed. Run the installer step below once, then keep the exe wherever you like.

## 🚀 Quick start

1. **Install Tor + config** (once): run the bundled installer in PowerShell 5.1+:
   ```powershell
   .\a.ps1                    # installs to F:\study\projects\IpRotator\runtime\AutoIpChanger
   .\a.ps1 -IntervalMinutes 45   # ...with a custom interval
   ```
   It downloads the official [Tor Expert Bundle](https://archive.torproject.org/tor-package-archive/torbrowser/13.5.6/), writes a BOM-free `torrc`, and starts rotating.

2. **Run the tray app**: launch `AutoIpChanger.exe`. An onion appears in your tray, **started disabled** (safety default) — click *Enable IP rotation* in the menu when you want rotation to begin.
   - **Hover** → current IP + its country + countdown to the next change (or your default IP while disabled)
   - **Right-click → Disable (use my default IP)** → pause rotation; the tray shows your default IP until you re-enable
   - **Right-click → Change IP now** → immediate rotation
   - **Right-click → Interval** → pick 1 / 5 / 10 / 15 / 30 / 45 / 60 / 90 / 120 minutes
   - **Right-click → Open log folder / Quit**

3. **Build your own exe** (optional, see below) or use the console launcher the installer provides.

## 🛠 Building the exe from source

```bat
pip install pystray pillow pyinstaller
cd src
python make_icon.py
python -m PyInstaller --onefile --noconsole --icon=tor_rotator.ico --name AutoIpChanger --hidden-import pystray._win32 tor_rotator_tray.py
```

## ⚙️ How it works

```
┌─────────────────────────────┐      AUTHENTICATE "" / SIGNAL NEWNYM
│  AutoIpChanger.exe (tray)   ─┬────────────────────────────────────►  Tor ControlPort :9051
│                             │
│  • supervises tor.exe       │       SOCKS5 CONNECT (checked against
│  • kills + restarts it if   ─┬──►   used_ips.json history)         Tor SocksPort   :9050
│    it stops responding      │                                        │
└─────────────────────────────┘                                        ▼
                                                    IP-echo services over HTTPS
                                              (check.torproject.org / ipify / ifconfig.me)
```

1. The app talks to Tor's **ControlPort** and verifies every `250 OK` reply — it never assumes success.
2. `SIGNAL NEWNYM` asks Tor for a fresh identity; the app waits for new circuits, then reads the **real exit IP** through Tor's SOCKS port.
3. If that IP is in `used_ips.json` → rotate again (up to 8 attempts per cycle).
4. The verified-fresh IP is recorded and announced. The whole cycle repeats on your interval.

### Data folder (survives reinstalls)

| File | Purpose |
|---|---|
| `used_ips.json` | Every IP ever used — the never-reuse guarantee (46+ and counting) |
| `current_ip.txt` | Your current IP, updated continuously |
| `ip_log.txt` | Timestamped log of every rotation and event |
| `settings.json` | `{"interval_minutes": 30, "enabled": true}` — editable live, applies next cycle |

Located at `F:\study\projects\IpRotator\runtime\AutoIpChanger-data` (next to the Tor install). The program folder is wiped and rebuilt by `a.ps1`; the data folder never is.

## ❓ Troubleshooting

- **No tray icon?** A second instance exits silently by design (single-instance mutex). Check Task Manager for `AutoIpChanger.exe`.
- **Rotation errors in the log?** See `tor\notice.log` — Tor's own log — for circuit/consensus issues.
- **"tor.exe not found"?** Run `.\a.ps1` once to install Tor first.
- **Console mode:** the installer's `Start-AutoIPChanger.bat` still works headless if you prefer it.

## ⚠️ Disclaimer

This tool changes your Tor exit IP on a schedule. Use it responsibly and legally — automated IP rotation does not make abuse anonymous or acceptable, and it may violate the terms of services you access. Tor Project trademarks belong to The Tor Project, Inc.; this project is not affiliated with or endorsed by them.

## 📄 License

[MIT](LICENSE) © 2026 Michaelunkai
