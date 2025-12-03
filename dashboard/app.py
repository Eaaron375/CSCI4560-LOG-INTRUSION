from flask import Flask, render_template
import mysql.connector

app = Flask(__name__)

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "PASSWORD",
    "database": "Project"
}

def query_db(query, args=()):
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor()
    cursor.execute(query, args)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

@app.route("/")
def dashboard():
    total_logs = query_db("SELECT COUNT(*) FROM LOGINS;")[0][0]
    total_alerts = query_db("SELECT COUNT(*) FROM ALERTS;")[0][0]
    recent_alerts = query_db("""
        SELECT alert_id, alert_type, severity, created_at 
        FROM ALERTS 
        ORDER BY created_at DESC 
        LIMIT 10;
    """)
    blacklist = query_db("SELECT ip_address, reason, date_added FROM IP_BLACKLIST;")

    return render_template(
        "dashboard.html",
        total_logs=total_logs,
        total_alerts=total_alerts,
        recent_alerts=recent_alerts,
        blacklist=blacklist
    )

if __name__ == "__main__":
    app.run(debug=True)
