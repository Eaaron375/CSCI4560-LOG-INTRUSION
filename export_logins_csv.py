# export_logins_csv.py
import mysql.connector
import csv

# --------------------------
# Database configuration
# --------------------------
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "@eaf4i12",
    "database": "Project"
}

# --------------------------
# Connect to MySQL
# --------------------------
conn = mysql.connector.connect(**DB_CONFIG)
cursor = conn.cursor()

# --------------------------
# Query LOGINS table
# --------------------------
cursor.execute("SELECT log_id, user_id, event_time, ip_address, status FROM LOGINS")
rows = cursor.fetchall()

# --------------------------
# Write to CSV
# --------------------------
with open("logins_export.csv", "w", newline="") as f:
    writer = csv.writer(f)
    # Write header
    writer.writerow(["log_id", "user_id", "event_time", "ip_address", "status"])
    # Write data
    writer.writerows(rows)

print(f"Exported {len(rows)} rows to logins_export.csv")

# --------------------------
# Cleanup
# --------------------------
cursor.close()
conn.close()