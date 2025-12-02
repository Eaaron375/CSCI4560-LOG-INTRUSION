# anomaly_detector.py
import time
import mysql.connector
from datetime import datetime, timedelta

DB_CFG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "@eaf4i12",
    "database": "Project"
}

def run_queries(conn, cursor):

    # ------------------------------
    # 1. BRUTE FORCE DETECTION
    # ------------------------------
    brute_force_sql = """
        SELECT l.user_id, COUNT(*) AS failures,
               MIN(l.log_id), MAX(l.log_id)
        FROM LOGINS l
        WHERE l.status='failure'
          AND l.event_time >= NOW() - INTERVAL 10 MINUTE
          AND l.processed = 0
        GROUP BY l.user_id
        HAVING failures >= 5;
    """

    cursor.execute(brute_force_sql)

    for user_id, failures, first_log_id, last_log_id in cursor.fetchall():
        desc = f"User {user_id} has {failures} failed logins in the last 10 minutes."

        print("⚠ BRUTE FORCE ALERT →", desc)

        cursor.execute("""
            INSERT INTO ALERTS (log_id, alert_type, severity, description)
            VALUES (%s, %s, %s, %s)
        """, (last_log_id, "brute_force", "high", desc))

        cursor.execute("""
            UPDATE LOGINS 
            SET processed = 1
            WHERE user_id=%s 
              AND status='failure'
              AND event_time >= NOW() - INTERVAL 10 MINUTE
        """, (user_id,))


    # ------------------------------
    # 2. OFF HOURS LOGIN DETECTION
    # ------------------------------
    off_hours_sql = """
        SELECT log_id, user_id, event_time, ip_address
        FROM LOGINS
        WHERE processed = 0
          AND status='success'
          AND (HOUR(event_time) < 6 OR HOUR(event_time) >= 20)
        LIMIT 50;
    """

    cursor.execute(off_hours_sql)

    for log_id, user_id, event_time, ip in cursor.fetchall():
        desc = f"Off-hours login by user {user_id} at {event_time} from {ip}"

        print("🌙 OFF-HOURS ALERT →", desc)

        cursor.execute("""
            INSERT INTO ALERTS (log_id, alert_type, severity, description)
            VALUES (%s, %s, %s, %s)
        """, (log_id, "off_hours", "medium", desc))

        cursor.execute("UPDATE LOGINS SET processed=1 WHERE log_id=%s", (log_id,))


    # ------------------------------
    # 3. BLACKLISTED IP DETECTION (optional table)
    # ------------------------------
    cursor.execute("SHOW TABLES LIKE 'IP_BLACKLIST'")
    if cursor.fetchone():   # table exists
        ip_blacklist_sql = """
            SELECT l.log_id, l.user_id, l.ip_address
            FROM LOGINS l
            JOIN IP_BLACKLIST b ON l.ip_address = b.ip_address
            WHERE l.processed = 0
            LIMIT 50;
        """
        cursor.execute(ip_blacklist_sql)

        for log_id, user_id, ip in cursor.fetchall():
            desc = f"Login from blacklisted IP {ip} by user {user_id}"

            print("🚫 BLACKLIST ALERT →", desc)

            cursor.execute("""
                INSERT INTO ALERTS (log_id, alert_type, severity, description)
                VALUES (%s, %s, %s, %s)
            """, (log_id, "blacklist_ip", "high", desc))

            cursor.execute("UPDATE LOGINS SET processed=1 WHERE log_id=%s", (log_id,))


    conn.commit()


def main():
    conn = mysql.connector.connect(**DB_CFG)
    cursor = conn.cursor()
    print("✔ Anomaly Detector Connected to Project DB")

    try:
        while True:
            run_queries(conn, cursor)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping detector.")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()