import sqlite3
import random
from datetime import datetime, timedelta

conn = sqlite3.connect("events.db")
cursor = conn.cursor()

# A handful of fake but realistic-looking attacker IPs
demo_ips = ["203.0.113.45", "198.51.100.22", "192.0.2.77", "203.0.113.9"]

now = datetime.now()

def insert_event(ip, event_type, details, minutes_ago):
    ts = (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO events (timestamp, ip, event_type, details) VALUES (?, ?, ?, ?)",
        (ts, ip, event_type, details)
    )

# Simulate 3 separate attack sessions spread across the last hour
minute_offset = 55
for ip in demo_ips[:3]:
    fail_count = 0
    for _ in range(random.randint(5, 8)):
        fail_count += 1
        insert_event(ip, "failed_login", f"count={fail_count}", minute_offset)
        minute_offset -= random.uniform(0.2, 0.6)
    insert_event(ip, "blocked", f"count={fail_count}", minute_offset)
    minute_offset -= 5
    insert_event(ip, "unblocked", "", minute_offset)
    minute_offset -= random.randint(8, 15)

conn.commit()
conn.close()
print("Demo data inserted.")