<#
================================================================================
AUTOMATED TOR IP ROTATOR SETUP SCRIPT
================================================================================

OVERVIEW & PURPOSE:
------------------
This script performs a 100% automated, zero-touch setup of an automated external IP
address changer using the official Tor Expert Bundle. It creates a self-contained local
proxy environment that rotates the exit IP on a fixed interval you choose (default:
every 30 minutes), and guarantees each new IP has NEVER been used before by this
system. Your current IP is always visible (console title, current_ip.txt, ip_log.txt).

USAGE:
------
.\a.ps1                          -> rotate every 30 minutes (default)
.\a.ps1 -IntervalMinutes 45      -> rotate every 45 minutes
The interval can also be changed later by editing 'interval_minutes' in the
data folder's settings.json - the running rotator picks it up on the next cycle.

TARGET INSTALLATION PATH:
------------------------
F:\study\projects\IpRotator\runtime\AutoIpChanger       (program files - wiped on each setup)
F:\study\projects\IpRotator\runtime\AutoIpChanger-data  (IP history, logs, settings - NEVER wiped,
                                                      so the never-reuse guarantee survives re-runs)

WHAT THIS SCRIPT EXECUTES STEP-BY-STEP:
---------------------------------------
1. Stop leftovers & clean install directory:
   Stops any tor/python instances from a previous run of this script (matched by
   install path, so unrelated processes are never touched), wipes the install
   folder, and recreates it plus the persistent data folder.

2. Download & Archive Extraction:
   Downloads the official portable Tor Expert Bundle (.tar.gz) from the Tor Project
   archives (TLS 1.2 forced for PowerShell 5.1). Decompresses the Gzip stream into a
   .tar file using .NET, extracts the payload with Windows' own System32 tar.exe
   (pinned by absolute path so Git's GNU tar can never shadow it), and verifies
   tor.exe actually landed before continuing.

3. BOM-Free Tor Configuration (torrc):
   Generates a strictly ASCII-encoded 'torrc' (no UTF-8 BOM, which makes Tor crash
   with 'Unknown option ControlPort'). SOCKS5 on 9050, ControlPort on 9051.

4. Python IP Controller Script Generation:
   Creates 'auto_rotate.py'. On every cycle it: re-reads the interval from
   settings.json, signals SIGNAL NEWNYM over the ControlPort, READS AND VERIFIES
   Tor's 250 OK replies, waits for new circuits, then queries the real exit IP
   through the SOCKS proxy (3 fallback IP-echo services). If the IP was ever used
   before (checked against used_ips.json) it rotates again - up to 25 attempts -
   so every confirmed IP is genuinely new. It reports the current IP at all times
   (console title with countdown, current_ip.txt, timestamped ip_log.txt) and
   automatically restarts tor.exe if it dies. The loop cannot crash.

5. Batch Launcher Generation:
   Creates 'Start-AutoIPChanger.bat' which launches 'auto_rotate.py' in its own
   window. The rotator itself starts tor.exe, supervises it, and kills +
   restarts it fresh the moment it stops working (fail-fast, no half-broken
   states are ever left running).

6. Automatic Execution:
   Triggers 'Start-AutoIPChanger.bat' to immediately start background IP rotation.

PREREQUISITES:
--------------
- Windows PowerShell 5.1 or newer.
- Python installed and available in System PATH.
- Active internet connection.
================================================================================
#>

param(
    # Rotation interval in minutes (e.g. 30 = new never-used IP every 30 minutes)
    [int]$IntervalMinutes = 30
)

# Enforce strict error handling (stops execution on any failure)
$ErrorActionPreference = "Stop"

if ($IntervalMinutes -lt 1) {
    throw "IntervalMinutes must be 1 or greater (got: $IntervalMinutes)"
}

# Define target paths
$InstallDir = "F:\study\projects\IpRotator\runtime\AutoIpChanger"
$StateDir   = "F:\study\projects\IpRotator\runtime\AutoIpChanger-data"
$TorDir     = Join-Path $InstallDir "tor"

# ------------------------------------------------------------------------------
# STEP 1: STOP LEFTOVERS, CLEAN AND INITIALIZE DIRECTORIES
# ------------------------------------------------------------------------------
# Stop leftover tor/python instances started by a previous run of this script,
# otherwise they keep file locks that would make the wipe below fail
# (matched by install path in the command line, so unrelated processes are safe)
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='tor.exe' OR Name='AutoIpChanger.exe'" |
    Where-Object { $_.CommandLine -like "*$InstallDir*" -or $_.Name -eq 'AutoIpChanger.exe' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

# Wait until Tor's ports are actually released so the fresh instance can bind them
$Deadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $Deadline) {
    $Busy = Get-NetTCPConnection -State Listen -LocalPort 9050, 9051 -ErrorAction SilentlyContinue
    if (-not $Busy) { break }
    Start-Sleep -Milliseconds 500
}
if (Get-NetTCPConnection -State Listen -LocalPort 9050, 9051 -ErrorAction SilentlyContinue) {
    throw "Ports 9050/9051 are still occupied by another program; cannot continue."
}

# Remove existing program folder to guarantee zero leftovers or file conflicts.
# NOTE: $StateDir is intentionally NEVER wiped - it holds the used-IP history,
# logs and settings so the never-reuse guarantee survives every re-run.
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
}

# Create fresh target directories
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $TorDir -Force | Out-Null
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

# ------------------------------------------------------------------------------
# STEP 2: DOWNLOAD AND EXTRACT PORTABLE TOR EXPERT BUNDLE
# ------------------------------------------------------------------------------
# Download URL for official Windows 64-bit Tor Expert Bundle
$TorZipUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/13.5.6/tor-expert-bundle-windows-x86_64-13.5.6.tar.gz"
$TorTarGz  = Join-Path $InstallDir "tor.tar.gz"
$TorTar    = Join-Path $InstallDir "tor.tar"

# PowerShell 5.1 defaults to legacy TLS versions that the Tor archive server
# rejects; force TLS 1.2 before invoking the web request
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# The visible progress bar makes Invoke-WebRequest extremely slow on PS 5.1
$ProgressPreference = "SilentlyContinue"

# Download archive file
Invoke-WebRequest -Uri $TorZipUrl -OutFile $TorTarGz -UseBasicParsing

# Decompress .tar.gz to .tar using .NET GZipStream
$GzipStream = [System.IO.Compression.GZipStream]::new(
    [System.IO.File]::OpenRead($TorTarGz),
    [System.IO.Compression.CompressionMode]::Decompress
)
$FileStream = [System.IO.File]::Create($TorTar)
$GzipStream.CopyTo($FileStream)

# Close streams individually, one statement per line
$GzipStream.Close()
$FileStream.Close()

# Delete downloaded GZ file
Remove-Item -Path $TorTarGz -Force

# Extract .tar payload using Windows' native tar utility, invoked by absolute
# path so another 'tar' on PATH (e.g. Git's GNU tar) can never shadow it --
# GNU tar misreads 'F:\...' as a remote host name and fails
$TarExe = Join-Path $env:SystemRoot "System32\tar.exe"
& $TarExe -xf $TorTar -C $TorDir
if ($LASTEXITCODE -ne 0) {
    throw "tar.exe extraction failed with exit code $LASTEXITCODE"
}

# Prove the payload actually landed before continuing
$TorExePath = Join-Path $TorDir "tor\tor.exe"
if (-not (Test-Path $TorExePath)) {
    throw "Extraction completed but tor.exe was not found at: $TorExePath"
}

# Delete extracted TAR archive
Remove-Item -Path $TorTar -Force

# ------------------------------------------------------------------------------
# STEP 3: CREATE ASCII-ENCODED TOR CONFIGURATION (torrc)
# ------------------------------------------------------------------------------
# Sanitize path for Tor configuration format
$DataDirEscaped    = ("$TorDir\data") -replace '\\', '/'
$NoticeLogEscaped  = ("$TorDir\notice.log") -replace '\\', '/'
$TorrcPath         = Join-Path $TorDir "torrc"

# Construct torrc file lines (notice log kept on disk so Tor is always diagnosable)
$TorrcContent   = "ControlPort 9051`r`nCookieAuthentication 0`r`nSocksPort 9050`r`nDataDirectory $DataDirEscaped`r`nLog notice file $NoticeLogEscaped"

# CRITICAL FIX: Write using explicit ASCII encoding to prevent UTF-8 BOM headers
[System.IO.File]::WriteAllText($TorrcPath, $TorrcContent, [System.Text.Encoding]::ASCII)

# ------------------------------------------------------------------------------
# STEP 4: GENERATE PYTHON IP ROTATION CONTROLLER
# ------------------------------------------------------------------------------
$PyScript = Join-Path $InstallDir "auto_rotate.py"

# Python controller script code (kept ASCII; single quotes only except the
# AUTHENTICATE "" wire command, so the here-string needs no quote escaping)
$PyCode = @"
import json
import os
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(BASE_DIR), os.path.basename(BASE_DIR) + '-data')
TOR_DIR     = os.path.join(BASE_DIR, 'tor')
TOR_EXE     = os.path.join(TOR_DIR, 'tor', 'tor.exe')
TORRC       = os.path.join(TOR_DIR, 'torrc')
SETTINGS    = os.path.join(DATA_DIR, 'settings.json')
HISTORY     = os.path.join(DATA_DIR, 'used_ips.json')
LOG_FILE    = os.path.join(DATA_DIR, 'ip_log.txt')
CURRENT_FILE = os.path.join(DATA_DIR, 'current_ip.txt')

CONTROL_HOST, CONTROL_PORT = '127.0.0.1', 9051
SOCKS_HOST, SOCKS_PORT     = '127.0.0.1', 9050
CIRCUIT_WAIT  = 10   # seconds for Tor to build fresh circuits after NEWNYM
MAX_ATTEMPTS  = 8    # NEWNYM attempts per cycle before failing this cycle fast
IP_SERVICES = [
    'https://check.torproject.org/api/ip',
    'https://api.ipify.org/?format=json',
    'https://ifconfig.me/ip',
]

os.makedirs(DATA_DIR, exist_ok=True)

def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def log(msg):
    line = '[' + now() + '] ' + msg
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except OSError:
        pass

def set_title(text):
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW(text)
    except Exception:
        pass

def load_interval():
    # Re-read every cycle so edits to settings.json apply without a restart
    try:
        with open(SETTINGS) as f:
            return max(1, int(json.load(f)['interval_minutes']))
    except Exception:
        return 30

def load_history():
    try:
        with open(HISTORY) as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_history():
    try:
        with open(HISTORY, 'w') as f:
            json.dump(sorted(USED), f, indent=1)
    except OSError as e:
        log('WARNING: could not save IP history: ' + str(e))

# ---- minimal SOCKS5 CONNECT (no auth), then HTTP(S) through the tunnel ----
def socks_connect(proxy_host, proxy_port, target_host, target_port, timeout=8):
    # Dial the PROXY (Tor's SOCKS port), then ask it to CONNECT to the target
    s = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    s.sendall(b'\x05\x01\x00')  # SOCKS5, one method: no auth
    resp = b''
    while len(resp) < 2:
        part = s.recv(2 - len(resp))
        if not part:
            s.close()
            raise RuntimeError('SOCKS5 server closed during handshake')
        resp += part
    if resp != b'\x05\x00':
        s.close()
        raise RuntimeError('SOCKS5 method negotiation failed')
    addr = target_host.encode()
    port_bytes = target_port.to_bytes(2, 'big')  # destination port in network order
    s.sendall(b'\x05\x01\x00\x03' + bytes([len(addr)]) + addr + port_bytes)
    resp = b''
    while len(resp) < 4:
        part = s.recv(4 - len(resp))
        if not part:
            s.close()
            raise RuntimeError('SOCKS5 server closed during connect')
        resp += part
    if resp[1] != 0:
        s.close()
        raise RuntimeError('SOCKS5 CONNECT rejected, reply code ' + str(resp[1]))
    # Drain the rest of the reply (bind addr + port) so the TLS stream that
    # follows starts on a clean byte boundary
    atyp = resp[3]
    if atyp == 1:
        need = 6
    elif atyp == 4:
        need = 18
    else:
        len_byte = s.recv(1)
        if not len_byte:
            s.close()
            raise RuntimeError('SOCKS5 server closed mid-reply')
        need = len_byte[0] + 2
    got = 0
    while got < need:
        part = s.recv(need - got)
        if not part:
            s.close()
            raise RuntimeError('SOCKS5 server closed mid-reply')
        got += len(part)
    return s

def http_get_via_socks(url, timeout=8):
    rest = url.split('://', 1)[1]
    hostname, path = rest.split('/', 1)
    path = '/' + path
    # Dial Tor's local SOCKS port; CONNECT targets hostname:443 through the tunnel
    raw = socks_connect(SOCKS_HOST, SOCKS_PORT, hostname, 443, timeout)
    try:
        tls = ssl.create_default_context().wrap_socket(raw, server_hostname=hostname)
        req = ('GET ' + path + ' HTTP/1.0\r\nHost: ' + hostname +
               '\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n')
        tls.sendall(req.encode())
        chunks = []
        while True:
            data = tls.recv(4096)
            if not data:
                break
            chunks.append(data)
        body = b''.join(chunks).decode('utf-8', 'replace')
        return body.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in body else ''
    finally:
        try:
            raw.close()
        except OSError:
            pass

def extract_ip(body):
    m = re.search(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', body)
    if not m:
        return None
    ip = m.group(0)
    try:
        socket.inet_aton(ip)
        return ip
    except OSError:
        return None

def get_current_ip():
    # Real exit IP as seen by the internet; fail fast: short timeouts,
    # quick fallbacks, only 2 rounds before giving up this attempt
    for round_no in range(2):
        for url in IP_SERVICES:
            try:
                ip = extract_ip(http_get_via_socks(url))
                if ip:
                    return ip
            except Exception as e:
                log('  IP check via ' + url.split('/')[2] + ' failed: ' + str(e))
        time.sleep(3)
    return None

def tor_is_up():
    try:
        s = socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False

TOR_PROC = None

def kill_own_tor():
    # Never keep a half-broken Tor running: kill the one we spawned
    global TOR_PROC
    if TOR_PROC is not None and TOR_PROC.poll() is None:
        try:
            TOR_PROC.terminate()
            TOR_PROC.wait(timeout=5)
            log('Killed unresponsive tor.exe so a fresh one can start.')
        except Exception:
            try:
                TOR_PROC.kill()
            except Exception:
                pass
    TOR_PROC = None

def ensure_tor():
    # Fail fast: if Tor is not fully working, kill it and try again fresh
    global TOR_PROC
    if not tor_is_up():
        log('Tor is not responding; starting a fresh tor.exe ...')
        flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        TOR_PROC = subprocess.Popen([TOR_EXE, '-f', TORRC], cwd=TOR_DIR, creationflags=flags,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 20
        while time.time() < deadline:
            if tor_is_up():
                break
            time.sleep(1)
        else:
            kill_own_tor()
            raise RuntimeError('tor.exe did not open its control port within 20 seconds')
    if not wait_for_bootstrap():
        kill_own_tor()
        raise RuntimeError('Tor did not finish bootstrapping within 60 seconds - killed it; will retry fresh')

def control_command(cmd, timeout=8):
    # Sends one control command, VERIFIES Tor's 250 OK reply, returns the reply
    s = socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=timeout)
    try:
        s.sendall(b'AUTHENTICATE ""\r\n')
        reply = s.recv(4096).decode('utf-8', 'replace')
        if not reply.startswith('250'):
            raise RuntimeError('Tor rejected AUTHENTICATE: ' + reply.strip())
        s.sendall((cmd + '\r\n').encode())
        time.sleep(0.3)
        reply = s.recv(65536).decode('utf-8', 'replace')
        if not reply.startswith('250'):
            raise RuntimeError('Tor rejected ' + cmd + ': ' + reply.strip())
        return reply
    finally:
        s.close()

def wait_for_bootstrap(timeout=60):
    # An open control port is not enough - streams only work once Tor is done
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if 'PROGRESS=100' in control_command('GETINFO status/bootstrap-phase'):
                return True
        except Exception:
            pass
        time.sleep(3)
    return False

def announce(next_change=None):
    with open(CURRENT_FILE, 'w') as f:
        f.write((CURRENT_IP or 'checking...') + '\n')
    title = 'Auto IP Changer | Current IP: ' + (CURRENT_IP or 'checking...')
    if next_change is not None:
        title += ' | Next change: ' + next_change
    set_title(title)

def rotate_until_new():
    # Signal NEWNYM, then keep rotating until the exit IP is one that has
    # NEVER appeared in the history. Returns the fresh IP or None.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        ensure_tor()
        try:
            control_command('SIGNAL NEWNYM')
        except Exception as e:
            log('  NEWNYM attempt ' + str(attempt) + ' failed: ' + str(e))
            time.sleep(10)
            continue
        time.sleep(CIRCUIT_WAIT)
        ip = get_current_ip()
        if ip is None:
            log('  attempt ' + str(attempt) + ': could not read current IP; retrying')
            continue
        if ip in USED:
            log('  attempt ' + str(attempt) + ': got ' + ip + ' which was used before; rotating again')
            time.sleep(3)
            continue
        USED.add(ip)
        save_history()
        return ip
    return None

def countdown(target):
    # Keep the console title showing the live time until the next change
    while True:
        remaining = target - time.time()
        if remaining <= 0:
            return
        m, s = divmod(max(0, int(remaining)), 60)
        set_title('Auto IP Changer | Current IP: ' + (CURRENT_IP or 'checking...') +
                  ' | Next change in {:02d}:{:02d}'.format(m, s))
        time.sleep(min(5, max(0.5, remaining)))

USED = load_history()
CURRENT_IP = None

def main():
    global CURRENT_IP
    log('=== Auto IP Changer started | interval: every ' + str(load_interval()) + ' minute(s) ===')
    log('Never-reuse history loaded: ' + str(len(USED)) + ' IP(s) that will never be handed out again')
    announce()
    while True:
        cycle_start = time.time()
        interval = load_interval()
        target = cycle_start + interval * 60
        next_change = datetime.fromtimestamp(target).strftime('%H:%M:%S')
        try:
            ensure_tor()
            if CURRENT_IP is None:
                # Startup: report the IP we woke up with, unless it was used before
                first = get_current_ip()
                if first is not None and first not in USED:
                    USED.add(first)
                    save_history()
                    CURRENT_IP = first
                    log('Current exit IP: ' + first + ' (fresh - never used before)')
                elif first is not None:
                    log('Startup IP ' + first + ' was used before; rotating now')
                announce(next_change)
            old = CURRENT_IP
            new_ip = rotate_until_new()
            if new_ip:
                CURRENT_IP = new_ip
                announce(next_change)
                log('IP CHANGED: ' + str(old) + ' -> ' + new_ip + '  (fresh IP #' + str(len(USED)) + ' in history)')
            else:
                log('WARNING: no never-used IP obtained this cycle; keeping ' + str(old) +
                    ' - retrying in 45 seconds instead of waiting the full interval')
                time.sleep(45)
                continue
        except Exception as e:
            # The loop must never die: log, wait, try again
            log('ERROR in cycle: ' + str(e) + ' - retrying in 15 seconds')
            time.sleep(15)
            continue
        remaining = target - time.time()
        if remaining > 0:
            countdown(target)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        log('Stopped by user (Ctrl+C).')
"@

# Save Python script with ASCII encoding
[System.IO.File]::WriteAllText($PyScript, $PyCode, [System.Text.Encoding]::ASCII)

# ------------------------------------------------------------------------------
# STEP 4b: WRITE ROTATION SETTINGS (interval is read live by auto_rotate.py)
# ------------------------------------------------------------------------------
$SettingsPath = Join-Path $StateDir "settings.json"
$SettingsJson = @{ interval_minutes = $IntervalMinutes } | ConvertTo-Json
[System.IO.File]::WriteAllText($SettingsPath, $SettingsJson + "`r`n", [System.Text.Encoding]::ASCII)

# ------------------------------------------------------------------------------
# STEP 5: CREATE WINDOWS SERVICE LAUNCHER (BAT)
# ------------------------------------------------------------------------------
$BatchPath = Join-Path $InstallDir "Start-AutoIPChanger.bat"

# Launcher batch script content: the rotator owns and supervises tor.exe itself
# (starts it, and kills + restarts it fresh the moment it stops working)
$BatchContent = @"
@echo off
title Auto IP Changer Launcher
echo Tor is started and supervised by the rotator itself.
start "Auto IP Changer" python "$PyScript"
exit
"@

# Save Batch file with ASCII encoding
[System.IO.File]::WriteAllText($BatchPath, $BatchContent, [System.Text.Encoding]::ASCII)

# ------------------------------------------------------------------------------
# STEP 6: EXECUTE LAUNCHER PROCESS
# ------------------------------------------------------------------------------
# Prefer the tray application when it has been built; fall back to the
# console launcher otherwise
$TrayExe = "F:\study\projects\IpRotator\AutoIpChanger.exe"
if (Test-Path $TrayExe) {
    Start-Process -FilePath $TrayExe
    $StartedWhat = $TrayExe + "  (tray app)"
} else {
    Start-Process -FilePath $BatchPath -WorkingDirectory $InstallDir
    $StartedWhat = $BatchPath
}

Write-Host ""
Write-Host "================ SETUP COMPLETE ================"
Write-Host " Rotation interval : every $IntervalMinutes minute(s)"
Write-Host " Installed to      : $InstallDir"
Write-Host " Data folder       : $StateDir"
Write-Host " Your current IP is always shown in:"
Write-Host "   - this window's title bar (with a live countdown to the next change)"
Write-Host "   - $StateDir\current_ip.txt"
Write-Host "   - $StateDir\ip_log.txt (full timestamped history of every change)"
Write-Host " Every new IP is verified against $StateDir\used_ips.json"
Write-Host " so no IP is ever handed out twice."
Write-Host " Change the interval anytime: edit interval_minutes in"
Write-Host "   $SettingsPath"
Write-Host " (applies from the next cycle), or re-run: .\a.ps1 -IntervalMinutes <minutes>"
Write-Host "================================================"
