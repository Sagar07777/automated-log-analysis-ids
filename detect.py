mport sqlite3
import time
import re
import subprocess

log_file = open("/var/log/auth.log", "r")
log_file.seek(0, 2)

pattern = re.compile(r"Failed password for \S+ from (\d+\.\d+\.\d+\.\d+) port")

failed_attempts = {}
THRESHOLD = 5
WINDOW = 60
BLOCK_DURATION = 300

ALLOWLIST = {"192.168.1.4", "192.168.1.9"}
blocked_ips = {}

def block_ip(ip):
    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    print(f"[+] Executed iptables block for {ip}")

def unblock_ip(ip):
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    print(f"[+] Executed unblock for {ip}")
    log_event(ip, "unblocked")

def init_db():
    conn = sqlite3.connect("events.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            event_type TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_event(ip, event_type, details=""):
    conn = sqlite3.connect("events.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (timestamp, ip, event_type, details) VALUES (?, ?, ?, ?)",
(time.strftime("%Y-%m-%d %H:%M:%S"), ip, event_type, details)
    )
    conn.commit()
    conn.close()
init_db()
while True:
    line = log_file.readline()

    # This now runs EVERY loop cycle, not just when a match happens
    now = time.time()
    for ip in list(blocked_ips.keys()):
        if now - blocked_ips[ip] > BLOCK_DURATION:
            unblock_ip(ip)
            del blocked_ips[ip]

    if not line:
        time.sleep(1)
        continue

    match = pattern.search(line)
    if match:
        ip = match.group(1)
        now = time.time()

        if ip in ALLOWLIST:
            print(f"[INFO] IP {ip} is allowlisted. Ignoring attempt.")
            log_event(ip, "allowlisted_attempt", "ignored - never blocked")
            continue

        if ip not in failed_attempts:
            failed_attempts[ip] = []

        failed_attempts[ip].append(now)
        failed_attempts[ip] = [t for t in failed_attempts[ip] if now - t <= WINDOW]

        count = len(failed_attempts[ip])
        print(f"Failed login from {ip} (count in last {WINDOW}s: {count})")
        
        log_event(ip, "failed_login", f"count={count}")

        if count >= THRESHOLD:
            if ip in blocked_ips:
                print(f"[!] IP {ip} is already blocked.")
            else:
                block_ip(ip)
 blocked_ips[ip] = now
                print(f"[ALERT] IP {ip} exceeded threshold! BLOCKED.")
                
                log_event(ip, "blocked", f"count={count}")
