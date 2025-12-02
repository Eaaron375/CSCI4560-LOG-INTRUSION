# log_parser.py
from faker import Faker
import random, datetime, mysql.connector, time

fake = Faker()

conn = mysql.connector.connect(
    host="localhost",
    port=3306,
    user="root",
    password="@eaf4i12",
    database="Project"
)
cursor = conn.cursor()

print("✔ Connected to MySQL (Project.LOGINS)")

while True:
    username = fake.user_name()
    ip = fake.ipv4_public()
    status = random.choice(["success", "failure"])
    event_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # For now: always user_id = 1  
    query = """
        INSERT INTO LOGINS (user_id, event_time, ip_address, status, processed)
        VALUES (%s, %s, %s, %s, 0)
    """
    cursor.execute(query, (1, event_time, ip, status))
    conn.commit()

    print(f"Inserted → {event_time} | {username} | {ip} | {status}")
    time.sleep(1)
