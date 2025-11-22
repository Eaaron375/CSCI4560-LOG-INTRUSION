import mysql.connector
import random
import time
from datetime import datetime, timedelta
from faker import Faker

fake = Faker()

# ---------------------------
#  CONFIGURE YOUR DATABASE
# ---------------------------
DB_CONFIG = 
{
    "user":     "root",      # <-- UPDATE
    "password": "@eaf4i12",  # <-- UPDATE
    "host":     "127.0.0.1",
    "database": "Project"
}

# ---------------------------
#  USERS TO PRELOAD
# ---------------------------
DEFAULT_USER_COUNT = 20

# ---------------------------
#  LOGIN EVENT SETTINGS
# ---------------------------
EVENTS_PER_MINUTE = 10
BRUTE_FORCE_CHANCE = 0.10   # 10% of the time simulate an attack
MAX_FAILURES = 7


def connect_db():
    """Establish MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


def initialize_users(cursor):
    """Insert some sample users if USERS table is empty."""
    cursor.execute("SELECT COUNT(*) FROM USERS")
    count = cursor.fetchone()[0]

    if count > 0:
        print("[INFO] USERS already populated.")
        return

    print(f"[INFO] Creating {DEFAULT_USER_COUNT} sample users...")

    for _ in range(DEFAULT_USER_COUNT):
        username = fake.user_name()
        password_hash = fake.sha256()
        cursor.execute(
            "INSERT INTO USERS (username, password_hash) VALUES (%s, %s)",
            (username, password_hash)
        )


def simulated_login_event(cursor, conn):
    """Generate and insert one login event."""
    # select random user
    cursor.execute("SELECT user_id FROM USERS ORDER BY RAND() LIMIT 1")
    user_id = cursor.fetchone()[0]

    ip_addr = fake.ipv4_public()
    status = random.choice(["success", "failure"])
    
    # brute force simulation
    if random.random() < BRUTE_FORCE_CHANCE:
        status = "failure"

    timestamp = datetime.now()

    cursor.execute("""
        INSERT INTO LOGINS (user_id, event_time, ip_address, status)
        VALUES (%s, %s, %s, %s)
    """, (user_id, timestamp, ip_addr, status))

    conn.commit()


def simulate_bruteforce(cursor, conn):
    """Force multiple failures to trigger the alert trigger."""
    cursor.execute("SELECT user_id FROM USERS ORDER BY RAND() LIMIT 1")
    user_id = cursor.fetchone()[0]
    ip_addr = fake.ipv4_public()

    print(f"[ALERT SIM] Simulating brute-force attack on user_id={user_id}")

    now = datetime.now()
    for _ in range(MAX_FAILURES):
        cursor.execute("""
            INSERT INTO LOGINS (user_id, event_time, ip_address, status)
            VALUES (%s, %s, %s, 'failure')
        """, (user_id, now, ip_addr))
        conn.commit()
        time.sleep(0.5)


def main_loop():
    conn = connect_db()
    cursor = conn.cursor()

    # initialize users
    initialize_users(cursor)
    conn.commit()

    print("[INFO] Starting event generator. CTRL+C to stop.")

    while True:
        try:
            if random.random() < BRUTE_FORCE_CHANCE:
                simulate_bruteforce(cursor, conn)
            else:
                for _ in range(EVENTS_PER_MINUTE):
                    simulated_login_event(cursor, conn)
                conn.commit()

            print("[INFO] Generated events...")
            time.sleep(60)

        except KeyboardInterrupt:
            print("\n[INFO] Stopping generator.")
            break


if __name__ == "__main__":
    main_loop()