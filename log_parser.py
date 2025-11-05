from faker import Faker
import random, datetime, mysql.connector, time

fake = Faker()

# Connect to MySQL
conn = mysql.connector.connect(
    host="127.0.0.1",
    port=3306,  # host-mapped port
    user="root",
    password="password",
    database="ids_db"
)
cursor = conn.cursor()

while True:
    user = fake.user_name()
    ip = fake.ipv4_public()
    status = random.choice(["success", "failure"])
    event_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    query = "INSERT INTO LOGINS (user_id, event_time, ip_address, status) VALUES (%s, %s, %s, %s)"
    cursor.execute(query, (1, event_time, ip, status))
    conn.commit()

    print(f"Inserted: {user} | {ip} | {status}")
    time.sleep(2)  # Simulate real-time incoming logs
