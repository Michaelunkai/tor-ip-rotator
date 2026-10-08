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

APP_VERSION = '1.1.0'

CONTROL_HOST, CONTROL_PORT = '127.0.0.1', 9051
SOCKS_HOST, SOCKS_PORT = '127.0.0.1', 9050
CIRCUIT_WAIT = 10    # seconds for Tor to build fresh circuits after NEWNYM
MAX_ATTEMPTS = 8     # NEWNYM attempts per cycle before failing this cycle fast
INTERVAL_CHOICES = [1, 5, 10, 15, 30, 45, 60, 90, 120]
# Geo services return the exit IP AND its country in one response
GEO_SERVICES = [
    ('https://get.geojs.io/v1/ip/geo.json', 'geojs'),
    ('https://ipwho.is/', 'ipwho'),
    ('https://ipapi.co/json/', 'ipapi'),
]
# Plain IP-only fallbacks (country unknown) if every geo service fails
PLAIN_SERVICES = [
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
ENABLED = True
DEFAULT_IP = None
CURRENT_COUNTRY = None
DEFAULT_COUNTRY = None
TOR_STOPPED_FOR_DISABLE = False

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

def load_settings():
    try:
        with open(SETTINGS) as f:
            s = json.load(f)
        return {'interval_minutes': max(1, int(s.get('interval_minutes', 30))),
                'enabled': bool(s.get('enabled', True))}
    except Exception:
        return {'interval_minutes': 30, 'enabled': True}

def save_settings():
    try:
        with open(SETTINGS, 'w') as f:
            json.dump({'interval_minutes': int(INTERVAL_MIN), 'enabled': bool(ENABLED)}, f)
        return True
    except OSError as e:
        log('WARNING: could not save settings: ' + str(e))
        return False

def set_interval(minutes):
    global INTERVAL_MIN
    INTERVAL_MIN = int(minutes)
    ok = save_settings()
    log('Interval changed to every ' + str(minutes) + ' minute(s).')
    return ok

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

def parse_geo(body, kind):
    # Returns (ip, country_name) from a geo service's JSON, or (None, None)
    try:
        data = json.loads(body)
    except Exception:
        return None, None
    if kind == 'geojs':
        ip, country = data.get('ip'), data.get('country') or data.get('country_code')
    elif kind == 'ipapi':
        ip, country = data.get('ip'), data.get('country_name') or data.get('country_code')
    elif kind == 'ipwho':
        if data.get('success') is False:
            return None, None
        ip, country = data.get('ip'), data.get('country')
    else:
        return None, None
    if ip:
        try:
            socket.inet_aton(ip)
        except OSError:
            return None, None
    return ip, (country.strip() if isinstance(country, str) and country.strip() else None)

def get_current_ip_country():
    # Real exit IP + its country, as seen through Tor; fail fast: short
    # timeouts, quick fallbacks, only 2 rounds before giving up this attempt
    for round_no in range(2):
        for url, kind in GEO_SERVICES:
            try:
                ip, country = parse_geo(http_get_via_socks(url), kind)
                if ip:
                    return ip, country
            except Exception as e:
                log('  geo check via ' + url.split('/')[2] + ' failed: ' + str(e))
        for url in PLAIN_SERVICES:
            try:
                ip = extract_ip(http_get_via_socks(url))
                if ip:
                    return ip, None
            except Exception as e:
                log('  IP check via ' + url.split('/')[2] + ' failed: ' + str(e))
        time.sleep(3)
    return None, None

def http_get_direct(url, timeout=6):
    rest = url.split('://', 1)[1]
    hostname, path = rest.split('/', 1)
    path = '/' + path
    raw = socket.create_connection((hostname, 443), timeout=timeout)
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

def get_default_ip_country():
    # The machine's normal (non-Tor) public IP + country, fetched DIRECTLY
    for round_no in range(2):
        for url, kind in [('https://get.geojs.io/v1/ip/geo.json', 'geojs'),
                          ('https://ipwho.is/', 'ipwho')]:
            try:
                ip, country = parse_geo(http_get_direct(url), kind)
                if ip:
                    return ip, country
            except Exception as e:
                log('  default-IP check via ' + url.split('/')[2] + ' failed: ' + str(e))
        try:
            ip = extract_ip(http_get_direct('https://api.ipify.org/?format=json'))
            if ip:
                return ip, None
        except Exception as e:
            log('  default-IP check via api.ipify.org failed: ' + str(e))
        time.sleep(3)
    return None, None

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
        if STOP_EVENT.is_set() or not ENABLED:
            return None
        ensure_tor()
        try:
            control_command('SIGNAL NEWNYM')
        except Exception as e:
            log('  NEWNYM attempt ' + str(attempt) + ' failed: ' + str(e))
            time.sleep(10)
            continue
        time.sleep(CIRCUIT_WAIT)
        ip, country = get_current_ip_country()
        if ip is None:
            log('  attempt ' + str(attempt) + ': could not read current IP; retrying')
            continue
        if ip in USED:
            log('  attempt ' + str(attempt) + ': got ' + ip + ' which was used before; rotating again')
            time.sleep(3)
            continue
        USED.add(ip)
        save_history()
        global CURRENT_COUNTRY
        CURRENT_COUNTRY = country
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
    if not ENABLED:
        t = 'Auto IP Changer v' + APP_VERSION + ' - DISABLED - default IP ' + (DEFAULT_IP or 'checking...')
    else:
        t = 'Auto IP Changer v' + APP_VERSION + ' - IP ' + (CURRENT_IP or 'checking...')
        if remaining is not None:
            m, s = divmod(max(0, int(remaining)), 60)
            t += ' - next change in %d:%02d' % (m, s)
    try:
        icon.title = t[:127]
    except Exception:
        pass

def on_change_now(icon, item):
    CHANGE_NOW_EVENT.set()

def on_toggle_enabled(icon, item):
    global ENABLED, CURRENT_IP, NEXT_CHANGE_TS
    ENABLED = not ENABLED
    save_settings()
    if ENABLED:
        log('Rotation ENABLED from tray menu - Tor will restart and a fresh never-used IP will be picked.')
        CURRENT_IP = None
        NEXT_CHANGE_TS = None
    else:
        log('Rotation DISABLED from tray menu - switching to the default IP ...')
        NEXT_CHANGE_TS = None

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
        pystray.MenuItem(lambda item: _status_text(), None, enabled=False),
        pystray.MenuItem(lambda item: _ip_text(), None, enabled=False),
        pystray.MenuItem(lambda item: _next_change_text(), None, enabled=False,
                         visible=lambda item: ENABLED),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(lambda item: 'Disable (use my default IP)' if ENABLED else 'Enable IP rotation',
                         on_toggle_enabled),
        pystray.MenuItem('Change IP now', on_change_now, visible=lambda item: ENABLED),
        pystray.MenuItem('Interval', pystray.Menu(*interval_items), visible=lambda item: ENABLED),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem('Open log folder', on_open_logs),
        pystray.MenuItem('Quit', on_quit),
    )

def _status_text():
    return ('Status: ENABLED - Tor rotation active' if ENABLED
            else 'Status: DISABLED - using your default IP')

def _ip_text():
    if ENABLED:
        return 'Current IP: ' + (CURRENT_IP or 'checking...') + (' (' + CURRENT_COUNTRY + ')' if CURRENT_COUNTRY else '')
    return 'Default IP: ' + (DEFAULT_IP or 'checking...') + (' (' + DEFAULT_COUNTRY + ')' if DEFAULT_COUNTRY else '')

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

def interruptible_sleep(seconds):
    # Sleep that ends immediately when the app is stopped or re-enabled
    end = time.time() + seconds
    while time.time() < end and not STOP_EVENT.is_set() and ENABLED:
        time.sleep(min(1, max(0.05, end - time.time())))

def worker(icon):
    global CURRENT_IP, NEXT_CHANGE_TS, INTERVAL_MIN, DEFAULT_IP, ENABLED, TOR_STOPPED_FOR_DISABLE
    global CURRENT_COUNTRY, DEFAULT_COUNTRY
    settings = load_settings()
    INTERVAL_MIN = settings['interval_minutes']
    ENABLED = settings['enabled']  # honor the persisted state at startup
    log('=== Auto IP Changer v' + APP_VERSION + ' (tray) started ===')
    log('Never-reuse history loaded: ' + str(len(USED)) + ' IP(s) that will never be handed out again')
    update_title(icon)
    while not STOP_EVENT.is_set():
        if not ENABLED:
            if not TOR_STOPPED_FOR_DISABLE:
                log('DISABLED: stopping Tor - traffic now uses the default IP.')
                stop_tor_gracefully()
                TOR_STOPPED_FOR_DISABLE = True
                CURRENT_IP = None
                NEXT_CHANGE_TS = None
                _notify(icon, 'Rotation off - using your default IP', 'Auto IP Changer disabled')
            ip, ctry = get_default_ip_country()
            if ip:
                DEFAULT_IP = ip
                DEFAULT_COUNTRY = ctry
                log('Default IP: ' + ip + (' (' + ctry + ')' if ctry else '') + ' (Tor rotation is off)')
            update_title(icon)
            try:
                with open(CURRENT_FILE, 'w') as f:
                    f.write((DEFAULT_IP or 'checking...') + '\n')
            except OSError:
                pass
            time.sleep(15)
            continue
        TOR_STOPPED_FOR_DISABLE = False
        cycle_start = time.time()
        INTERVAL_MIN = load_interval()
        target = cycle_start + INTERVAL_MIN * 60
        NEXT_CHANGE_TS = target
        try:
            ensure_tor()
            if CURRENT_IP is None:
                # Startup: report the IP we woke up with, unless it was used before
                first, first_country = get_current_ip_country()
                if first is not None and first not in USED:
                    USED.add(first)
                    save_history()
                    CURRENT_IP = first
                    CURRENT_COUNTRY = first_country
                    log('Current exit IP: ' + first + (' (' + first_country + ')' if first_country else '') +
                        ' (fresh - never used before)')
                    _notify(icon, 'Current IP: ' + first +
                            (' (' + first_country + ')' if first_country else ''), 'Auto IP Changer started')
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
                    (' (' + CURRENT_COUNTRY + ')' if CURRENT_COUNTRY else '') +
                    '  [fresh IP #' + str(len(USED)) + ' in history]')
                _notify(icon, 'New IP: ' + new_ip +
                        (' (' + CURRENT_COUNTRY + ')' if CURRENT_COUNTRY else ''),
                        'IP changed (#' + str(len(USED)) + ' fresh IPs used)')
            elif not ENABLED:
                continue
            else:
                log('WARNING: no never-used IP obtained this cycle; keeping ' + str(old) +
                    ' - retrying in 45 seconds instead of waiting the full interval')
                interruptible_sleep(45)
                continue
        except Exception as e:
            if not ENABLED:
                continue
            log('ERROR in cycle: ' + str(e) + ' - retrying in 15 seconds')
            interruptible_sleep(15)
            continue
        # countdown with live tooltip; exit early on quit, "change now", or disable
        while not STOP_EVENT.is_set():
            if CHANGE_NOW_EVENT.is_set():
                CHANGE_NOW_EVENT.clear()
                break
            if not ENABLED:
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
