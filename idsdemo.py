import mysql.connector
import time
import random
from faker import Faker
from datetime import datetime, timedelta
import hashlib
from collections import Counter

fake = Faker()

# ===============================================
# CONFIG
# ===============================================
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "@PASSWORD",
    "database": "Project"
}

EVENTS_PER_MINUTE = 200          # LOTS of logs
BRUTE_FORCE_CHANCE = 0.50        # 50% chance of an attack burst
MAX_FAILURES = 10                # Up to 10 failures in an attack
SUMMARY_INTERVAL = 10            # Print dashboard every 10 sec


# ===============================================
# UTILITY FUNCTIONS
# ===============================================
def random_event_time():
    """Simulate realistic login activity across weighted hours."""
    hour = random.choices(
        population=[2, 3, 12, 15, 18, 20, 21, 22, 23],
        weights=[15, 15, 5, 5, 10, 10, 15, 15, 10],
        k=1
    )[0]
    minute = random.randint(0, 59)
    second = random.randint(0, 59)

    now = datetime.now()
    return now.replace(hour=hour, minute=minute, second=second)


def generate_hash(user_id, ip, timestamp, status):
    """Hash log content for integrity."""
    content = f"{user_id}|{ip}|{timestamp}|{status}"
    return hashlib.sha256(content.encode()).hexdigest()


# ===============================================
# IDS FUNCTIONS
# ===============================================
def create_users(cursor, conn, count=20):
    print("[INFO] Creating sample users...")

    cursor.execute("SELECT COUNT(*) FROM USERS;")
    existing = cursor.fetchone()[0]

    if existing >= count:
        print("[INFO] Users already exist. Skipping.")
        return

    for i in range(count):
        username = f"user{i+1}"
        pwd_hash = hashlib.sha256(username.encode()).hexdigest()

        cursor.execute(
            "INSERT INTO USERS (username, password_hash) VALUES (%s, %s)",
            (username, pwd_hash)
        )

    conn.commit()
    print(f"[INFO] {count} users ready.")


def get_random_user(cursor):
    cursor.execute("SELECT user_id FROM USERS ORDER BY RAND() LIMIT 1;")
    return cursor.fetchone()[0]


def simulate_bruteforce(cursor, conn):
    """Burst of rapid failed logins."""
    attacker_ip = fake.ipv4()
    user_id = get_random_user(cursor)

    failures = random.randint(5, MAX_FAILURES)

    for _ in range(failures):
        timestamp = random_event_time()
        log_hash = generate_hash(user_id, attacker_ip, timestamp, "failure")

        cursor.execute("""
            INSERT INTO LOGINS (user_id, event_time, ip_address, status, log_hash)
            VALUES (%s, %s, %s, 'failure', %s)
        """, (user_id, timestamp, attacker_ip, log_hash))

    conn.commit()

    print(f"[ATTACK] Brute-force burst: {failures} failures from {attacker_ip} → user {user_id}")


def generate_login_event(cursor, conn):
    """Normal login (success or failure)."""
    user_id = get_random_user(cursor)
    ip_addr = fake.ipv4()
    timestamp = random_event_time()

    # 20% fail rate
    status = "failure" if random.random() < 0.2 else "success"

    log_hash = generate_hash(user_id, ip_addr, timestamp, status)

    # Insert into DB
    cursor.execute("""
        INSERT INTO LOGINS (user_id, event_time, ip_address, status, log_hash)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, timestamp, ip_addr, status, log_hash))

    conn.commit()


def check_blacklist(cursor, conn):
    """Return all blacklisted IPs as a set."""
    cursor.execute("SELECT ip_address FROM IP_BLACKLIST;")
    rows = cursor.fetchall()
    return {r[0] for r in rows}


# ===============================================
# SUMMARY DASHBOARD
# ===============================================
def print_summary(cursor):
    cursor.execute("SELECT COUNT(*) FROM LOGINS;")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM ALERTS;")
    total_alerts = cursor.fetchone()[0]

    # Top risky user
    cursor.execute("""
        SELECT user_id, COUNT(*) AS fails
        FROM LOGINS
        WHERE status='failure'
        GROUP BY user_id
        ORDER BY fails DESC
        LIMIT 1;
    """)
    row = cursor.fetchone()
    top_user = f"User {row[0]}" if row else "N/A"

    # Top malicious IP
    cursor.execute("""
        SELECT ip_address, COUNT(*) AS cnt
        FROM LOGINS
        WHERE status='failure'
        GROUP BY ip_address
        ORDER BY cnt DESC
        LIMIT 1;
    """)
    iprow = cursor.fetchone()
    top_ip = iprow[0] if iprow else "N/A"

    print("\n=== SUMMARY ===")
    print(f"Total logs: {total_logs}")
    print(f"Total alerts: {total_alerts}")
    print(f"Top risky user: {top_user}")
    print(f"Top bad IP: {top_ip}")
    print("================\n")


# ===============================================
# MAIN LOOP
# ===============================================
def main():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        print("[OK] Connected to database.\n")
    except Exception as e:
        print("[ERROR] DB connection failed:", e)
        return

    create_users(cursor, conn)

    print("[INFO] Starting IDS/IPS demo. CTRL+C to stop.\n")
    last_summary = time.time()

    try:
        while True:

            # Randomly simulate attacks
            if random.random() < BRUTE_FORCE_CHANCE:
                simulate_bruteforce(cursor, conn)

            # Normal traffic
            for _ in range(EVENTS_PER_MINUTE):
                generate_login_event(cursor, conn)

            # Periodic dashboard summary
            if time.time() - last_summary >= SUMMARY_INTERVAL:
                print_summary(cursor)
                last_summary = time.time()

            # Small delay to avoid maxing CPU
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[INFO] Stopping IDS/IPS demo.")
        cursor.close()
        conn.close()


if __name__ == "__main__":
    main()
