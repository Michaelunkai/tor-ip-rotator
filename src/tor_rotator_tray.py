"""
Auto IP Changer - system tray application
==========================================
Rotates the machine's public exit IP through Tor on a fixed interval and
guarantees every new IP has never been used before by this system.

Runs completely without a terminal: lives in the system tray, shows the
current IP + countdown in the tooltip, and offers a right-click menu
(change IP now, pick the interval, open logs, quit).

The fail-fast rules it lives by:
  * short timeouts everywhere - a problem is noticed in seconds
  * a Tor that is not fully working is killed and started fresh
  * a failed cycle retries in 45 s instead of waiting the whole interval
  * the main loop can never die
"""

import ctypes
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime

import pystray
from PIL import Image, ImageDraw

# ----------------------------------------------------------------------------
# Paths and constants
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0])) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
# Tor + torrc live in the folder created by a.ps1; the data folder (never wiped)
# sits next to it and holds history, logs and settings.
DEFAULT_INSTALL_DIR = r'F:\study\projects\IpRotator\runtime\AutoIpChanger'
DATA_DIR = r'F:\study\projects\IpRotator\runtime\AutoIpChanger-data'
TOR_DIR = os.path.join(DEFAULT_INSTALL_DIR, 'tor')
TOR_EXE = os.path.join(TOR_DIR, 'tor', 'tor.exe')
TORRC = os.path.join(TOR_DIR, 'torrc')
SETTINGS = os.path.join(DATA_DIR, 'settings.json')
HISTORY = os.path.join(DATA_DIR, 'used_ips.json')
LOG_FILE = os.path.join(DATA_DIR, 'ip_log.txt')
CURRENT_FILE = os.path.join(DATA_DIR, 'current_ip.txt')

CONTROL_HOST, CONTROL_PORT = '127.0.0.1', 9051
SOCKS_HOST, SOCKS_PORT = '127.0.0.1', 9050
CIRCUIT_WAIT = 10    # seconds for Tor to build fresh circuits after NEWNYM
MAX_ATTEMPTS = 8     # NEWNYM attempts per cycle before failing this cycle fast
INTERVAL_CHOICES = [1, 5, 10, 15, 30, 45, 60, 90, 120]
IP_SERVICES = [
    'https://check.torproject.org/api/ip',
    'https://api.ipify.org/?format=json',
    'https://ifconfig.me/ip',
]

os.makedirs(DATA_DIR, exist_ok=True)

# ----------------------------------------------------------------------------
# Single-instance guard: a second launch simply exits
# ----------------------------------------------------------------------------
_mutex = ctypes.windll.kernel32.CreateMutexW(None, False, 'AutoIpChanger_Tray_Mutex')
if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
    sys.exit(0)

# ----------------------------------------------------------------------------
# Shared state
# ----------------------------------------------------------------------------
USED = set()
CURRENT_IP = None
NEXT_CHANGE_TS = None
INTERVAL_MIN = 30
TOR_PROC = None
STOP_EVENT = threading.Event()
CHANGE_NOW_EVENT = threading.Event()

# ----------------------------------------------------------------------------
# Logging and small helpers
# ----------------------------------------------------------------------------
def now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def log(msg):
    line = '[' + now() + '] ' + msg
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except OSError:
        pass

def load_interval():
    # Re-read before every cycle so external edits apply without a restart
    try:
        with open(SETTINGS) as f:
            return max(1, int(json.load(f)['interval_minutes']))
    except Exception:
        return 30

def set_interval(minutes):
    try:
        with open(SETTINGS, 'w') as f:
            json.dump({'interval_minutes': int(minutes)}, f)
        log('Interval changed to every ' + str(minutes) + ' minute(s).')
        return True
    except OSError as e:
        log('WARNING: could not save interval: ' + str(e))
        return False

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

# ----------------------------------------------------------------------------
# Minimal SOCKS5 client (no auth) + HTTPS-over-SOCKS, no external deps
# ----------------------------------------------------------------------------
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
    port_bytes = target_port.to_bytes(2, 'big')
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
    # Drain the rest of the reply so the TLS stream starts on a clean boundary
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

# ----------------------------------------------------------------------------
# Tor supervision - fail fast, kill what is not fully working
# ----------------------------------------------------------------------------
def tor_is_up():
    try:
        s = socket.create_connection((CONTROL_HOST, CONTROL_PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False

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

def kill_own_tor():
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

def stop_tor_gracefully():
    global TOR_PROC
    try:
        if tor_is_up():
            control_command('SIGNAL SHUTDOWN', timeout=4)
            time.sleep(2)
    except Exception:
        pass
    kill_own_tor()

def ensure_tor():
    # Fail fast: if Tor is not fully working, kill it and try again fresh
    global TOR_PROC
    if not tor_is_up():
        log('Tor is not responding; starting a fresh tor.exe ...')
        if not os.path.isfile(TOR_EXE):
            raise RuntimeError('tor.exe not found at ' + TOR_EXE +
                               ' - run a.ps1 (the installer) first')
        flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        TOR_PROC = subprocess.Popen([TOR_EXE, '-f', TORRC], cwd=TOR_DIR,
                                    creationflags=flags,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL)
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

def rotate_until_new(icon):
    # Signal NEWNYM, then keep rotating until the exit IP is one that has
    # NEVER appeared in the history. Returns the fresh IP or None.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if STOP_EVENT.is_set():
            return None
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

# ----------------------------------------------------------------------------
# Tray icon artwork - purple Tor onion with a mint rotation arrow
# ----------------------------------------------------------------------------
def draw_icon(size=256):
    S = size * 4  # supersample for smooth edges
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = cy = S / 2
    R = S * 0.48
    # dark navy disc
    d.ellipse([cx - R, cy - R, cx + R, cy + R], fill=(22, 22, 46, 255))
    d.ellipse([cx - R, cy - R, cx + R, cy + R], outline=(78, 205, 196, 255), width=max(1, int(S * 0.012)))
    # onion rings, dark purple core to near-white centre
    rings = [
        (S * 0.30, (126, 71, 152, 255)),
        (S * 0.215, (155, 89, 182, 255)),
        (S * 0.14, (198, 160, 220, 255)),
        (S * 0.065, (250, 247, 255, 255)),
    ]
    for rr, col in rings:
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=col)
    # rotation arrow around the onion
    arc_r = S * 0.395
    w = max(1, int(S * 0.05))
    box = [cx - arc_r, cy - arc_r, cx + arc_r, cy + arc_r]
    d.arc(box, start=-55, end=205, fill=(78, 205, 196, 255), width=w)
    ang = math.radians(205)
    px, py = cx + arc_r * math.cos(ang), cy + arc_r * math.sin(ang)
    tx, ty = -math.sin(ang), math.cos(ang)   # tangent, direction of travel
    nx, ny = -ty, tx                          # normal
    h = S * 0.10
    p1 = (px + tx * h, py + ty * h)
    p2 = (px - tx * h * 0.25 + nx * h * 0.62, py - ty * h * 0.25 + ny * h * 0.62)
    p3 = (px - tx * h * 0.25 - nx * h * 0.62, py - ty * h * 0.25 - ny * h * 0.62)
    d.polygon([p1, p2, p3], fill=(78, 205, 196, 255))
    return img.resize((size, size), Image.LANCZOS)

# ----------------------------------------------------------------------------
# Tray UI plumbing
# ----------------------------------------------------------------------------
def update_title(icon, remaining=None):
    t = 'Auto IP Changer - IP ' + (CURRENT_IP or 'checking...')
    if remaining is not None:
        m, s = divmod(max(0, int(remaining)), 60)
        t += ' - next change in %d:%02d' % (m, s)
    try:
        icon.title = t[:127]
    except Exception:
        pass

def on_change_now(icon, item):
    CHANGE_NOW_EVENT.set()

def make_interval_action(minutes):
    def action(icon, item):
        set_interval(minutes)
        global INTERVAL_MIN
        INTERVAL_MIN = minutes
    return action

def make_interval_checked(minutes):
    def checked(item):
        return INTERVAL_MIN == minutes
    return checked

def on_open_logs(icon, item):
    subprocess.Popen(['explorer', DATA_DIR])

def on_quit(icon, item):
    log('Quit requested from tray menu - shutting down Tor ...')
    STOP_EVENT.set()
    threading.Thread(target=_shutdown, args=(icon,), daemon=True).start()

def _shutdown(icon):
    stop_tor_gracefully()
    log('Bye.')
    icon.stop()

def build_menu():
    interval_items = [
        pystray.MenuItem(
            (str(m) + ' minutes') if m != 1 else '1 minute',
            make_interval_action(m),
            checked=make_interval_checked(m),
            radio=True,
        )
        for m in INTERVAL_CHOICES
    ]
    return pystray.Menu(
        pystray.MenuItem(lambda item: 'Current IP: ' + (CURRENT_IP or 'checking...'), None, enabled=False),
        pystray.MenuItem(lambda item: _next_change_text(), None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('Change IP now', on_change_now),
        pystray.MenuItem('Interval', pystray.Menu(*interval_items)),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('Open log folder', on_open_logs),
        pystray.MenuItem('Quit', on_quit),
    )

def _next_change_text():
    if NEXT_CHANGE_TS is None:
        return 'Next change: scheduling...'
    remaining = NEXT_CHANGE_TS - time.time()
    if remaining <= 0:
        return 'Next change: any moment now'
    m, s = divmod(int(remaining), 60)
    if m >= 60:
        return 'Next change in %dh %02dm' % (m // 60, m % 60)
    return 'Next change in %d:%02d' % (m, s)

def worker(icon):
    global CURRENT_IP, NEXT_CHANGE_TS, INTERVAL_MIN
    log('=== Auto IP Changer (tray) started ===')
    log('Never-reuse history loaded: ' + str(len(USED)) + ' IP(s) that will never be handed out again')
    update_title(icon)
    while not STOP_EVENT.is_set():
        cycle_start = time.time()
        INTERVAL_MIN = load_interval()
        target = cycle_start + INTERVAL_MIN * 60
        NEXT_CHANGE_TS = target
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
                    _notify(icon, 'Current IP: ' + first, 'Auto IP Changer started')
                elif first is not None:
                    log('Startup IP ' + first + ' was used before; rotating now')
                update_title(icon)
            old = CURRENT_IP
            new_ip = rotate_until_new(icon)
            if new_ip:
                CURRENT_IP = new_ip
                NEXT_CHANGE_TS = target
                update_title(icon)
                log('IP CHANGED: ' + str(old) + ' -> ' + new_ip +
                    '  (fresh IP #' + str(len(USED)) + ' in history)')
                _notify(icon, 'New IP: ' + new_ip, 'IP changed (#' + str(len(USED)) + ' fresh IPs used)')
            else:
                log('WARNING: no never-used IP obtained this cycle; keeping ' + str(old) +
                    ' - retrying in 45 seconds instead of waiting the full interval')
                CURRENT_IP = CURRENT_IP  # unchanged
                time.sleep(45)
                continue
        except Exception as e:
            log('ERROR in cycle: ' + str(e) + ' - retrying in 15 seconds')
            time.sleep(15)
            continue
        # countdown with live tooltip; exit early on quit or "change now"
        while not STOP_EVENT.is_set():
            if CHANGE_NOW_EVENT.is_set():
                CHANGE_NOW_EVENT.clear()
                break
            remaining = target - time.time()
            if remaining <= 0:
                break
            update_title(icon, remaining)
            try:
                with open(CURRENT_FILE, 'w') as f:
                    f.write((CURRENT_IP or 'checking...') + '\n')
            except OSError:
                pass
            time.sleep(min(2, max(0.5, remaining)))
    log('Rotation loop stopped.')

def _notify(icon, message, title):
    try:
        icon.notify(message, title)
        threading.Timer(8.0, lambda: _safe_hide(icon)).start()
    except Exception:
        pass

def _safe_hide(icon):
    try:
        icon.remove_notification()
    except Exception:
        pass

def main():
    global USED
    USED = load_history()
    icon = pystray.Icon('AutoIpChanger', draw_icon(256), 'Auto IP Changer - starting...',
                        build_menu())

    def setup(ic):
        # A custom setup handler replaces pystray's default one, which is what
        # normally makes the icon visible - so show it explicitly, then work
        ic.visible = True
        threading.Thread(target=worker, args=(ic,), daemon=True).start()

    icon.run(setup=setup)

if __name__ == '__main__':
    main()
