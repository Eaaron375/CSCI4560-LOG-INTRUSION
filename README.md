README.txt
CSCI 4560 – Log Monitoring & Intrusion Detection Project
Author: Eaaron Foley
Version: Fall 2025
Project Overview

This project simulates a basic Intrusion Detection System (IDS) and Intrusion Prevention System (IPS) using:
	•	Python scripts
	•	MySQL database
	•	Flask web dashboard

The system performs the following:
	•	Generates log data (login events)
	•	Parses logs and inserts them into MySQL
	•	Detects anomalies (e.g., brute-force login attempts)
	•	Stores alerts in a database
	•	Displays a real-time dashboard showing system activity

This project acts as a small-scale SOC (Security Operations Center) pipeline with ETL-like behavior, IDS logic, and a front-end monitoring panel.
CSCI4560-LOG-INTRUSION/
│
├── python/
│   ├── generate_security_events.py
│   ├── log_parser.py
│   ├── anomaly_detector.py
│   ├── testconnection.py
│   ├── venv/  (optional)
│
├── dashboard/
│   ├── app.py
│   ├── templates/
│   │   └── dashboard.html
│
└── mysql/
    └── schema.sql

Requirements (Windows / macOS / Linux)
Install Python (3.8+)

Download from: https://www.python.org/downloads/
Install MySQL Server & Workbench

https://dev.mysql.com/downloads/

Ensure MySQL is running.
Install pip packages

Database Permissions & Configuration (IMPORTANT)

This project connects to a MySQL database using credentials defined inside the Python scripts.
Because every user has a different MySQL username, password, host, and database name, you MUST update the configuration before running any script.
Each Python file contains a section similar to:
DB_CONFIG = 
{
    "user": "root",
    "password": "PASSWORD", 
    "host": "127.0.0.1",
    "database": "Project"
}
Replace these fields with your own values

1. Clone the Reop
You will install these later inside the project.\
git clone https://github.com/Eaaron375/CSCI4560-LOG-INTRUSION
cd CSCI4560-LOG-INTRUSION

2. Create and Activate a Virtual Environment
Windows command:
python -m venv venv
venv\Scripts\activate

Mac / Linux command:
python3 -m venv venv
source venv/bin/activate

3. Install Python Dependencies
Command: pip install flask mysql-connector-python faker

4. Import the MySQL Schema
source /path/to/schema.sql;
Or from CLI:
mysql -u root -p < mysql/schema.sql
This will creates LOGINS, ALERTS, AND IP_BLACKLIST

5. Test Database Connection
DO THIS INSIDE OF THE PYTHON FOLDER: python3 testconnection.py
The you should see "[OK] Connected to MySQL!"

6. Start the Log Generator
STILL INSDIE THE PYTHON FOLDER:
python3 generate_security_events.py

7. Run the Log Parser
INSIDE OF A SEPARATE TERMINAL WINDOW:
python3 log_parser.py

8. Start the Anomaly Detector
INSIDE OF A SEPARATE TERMINAL WINDOW:
python3 anomaly_detector.py
Then you should see "⚠ BRUTE FORCE ALERT → User X has failed N times..."

9. Start the Flask Dashboard
GO TO THE DASHBOARD FOLDER:
cd dashboard
python3 app.py
OPEN IN BROWSER:
http://127.0.0.1:5000

Export logs for views in LookerStuido (optional)
python3 export_to_csv.py
