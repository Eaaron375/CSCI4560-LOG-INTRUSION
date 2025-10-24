import time
import mysql.connector
from datetime import datetime, timedelta

DB_CFG = {
    "host": "127.0.0.1",
    "port": 3307,
    "user": "root",
    "password": "password",
    "database": "ids_db"
}

def run_queries(conn, cursor):
    # 1) Brute-force: >5 failures in last 10 minutes per user
    brute_force_sql = """
    SELECT l.user_id, u.username, COUNT(*) AS failures,
           MIN(l.log_id) AS first_log_id, MAX(l.log_id) AS last_log_id
    FROM LOGINS l
    JOIN USERS u ON l.user_id = u.user_id
    WHERE l.status='failure' AND l.event_time >= NOW() - INTERVAL 10 MINUTE
      AND l.processed = 0
    GROUP BY l.user_id
    HAVING failures >= 5;
    """
    cursor.execute(brute_force_sql)
    for user_id, username, failures, first_log_id, last_log_id in cursor.fetchall():
        desc = f"User {username} ({user_id}) had {failures} failed logins in the last 10 minutes."
        print("BRUTE-FORCE ALERT:", desc)
        cursor.execute(
            "INSERT INTO ALERTS (log_id, alert_type, severity, description) VALUES (%s, %s, %s, %s)",
            (last_log_id, "brute_force", "high", desc)
        )
        cursor.execute("""
            UPDATE LOGINS
            SET processed = 1
            WHERE user_id = %s AND status='failure' AND event_time >= NOW() - INTERVAL 10 MINUTE
        """, (user_id,))

    # 2) Off-hours logins
    off_hours_sql = """
    SELECT l.log_id, l.user_id, u.username, l.event_time, l.ip_address
    FROM LOGINS l
    JOIN USERS u ON l.user_id = u.user_id
    WHERE l.processed = 0 AND l.status='success'
      AND (HOUR(l.event_time) < 6 OR HOUR(l.event_time) >= 20)
    LIMIT 100;
    """
    cursor.execute(off_hours_sql)
    for log_id, user_id, username, event_time, ip in cursor.fetchall():
        desc = f"Off-hours login by {username} at {event_time} from {ip}"
        print("OFF-HOURS ALERT:", desc)
        cursor.execute(
            "INSERT INTO ALERTS (log_id, alert_type, severity, description) VALUES (%s, %s, %s, %s)",
            (log_id, "off_hours", "medium", desc)
        )
        cursor.execute("UPDATE LOGINS SET processed=1 WHERE log_id=%s", (log_id,))

    # 3) IP blacklist check
    ip_blacklist_sql = """
    SELECT l.log_id, l.user_id, u.username, l.ip_address
    FROM LOGINS l
    JOIN IP_BLACKLIST b ON l.ip_address = b.ip_address
    JOIN USERS u ON l.user_id = u.user_id
    WHERE l.processed = 0
    LIMIT 100;
    """
    cursor.execute(ip_blacklist_sql)
    for log_id, user_id, username, ip in cursor.fetchall():
        desc = f"Login from blacklisted IP {ip} by {username}"
        print("BLACKLIST ALERT:", desc)
        cursor.execute(
            "INSERT INTO ALERTS (log_id, alert_type, severity, description) VALUES (%s, %s, %s, %s)",
            (log_id, "blacklist_ip", "high", desc)
        )
        cursor.execute("UPDATE LOGINS SET processed=1 WHERE log_id=%s", (log_id,))

    conn.commit()

def main():
    conn = mysql.connector.connect(**DB_CFG)
    cursor = conn.cursor()
    try:
        while True:
            run_queries(conn, cursor)
            time.sleep(10)
    except KeyboardInterrupt:
        print("Stopping detector.")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    main()
