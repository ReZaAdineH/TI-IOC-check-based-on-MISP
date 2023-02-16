import requests
import sqlite3
import time
import platform
import os
import socket
from flask import Flask, jsonify, request

# MISP API URL and authentication header
misp_url = "https://misp.local/attributes/restSearch"
headers = {
    "Authorization": "Your-MISP-API-Key",
    "Content-Type": "application/json"
}

# payload for sending a request to MISP API
payload = """
{
    "returnFormat": "json",
    "type": "ip-dst",
    "value": "1.1.1.1"
}
"""

# function to check if a given list of IOCs is present in the system
def check_ioc_presence(ioc_list):
    present_iocs = []
    not_present_iocs = []
    for ioc in ioc_list:
        try:
            socket.gethostbyname(ioc)
            present_iocs.append(ioc)
        except:
            not_present_iocs.append(ioc)
    return present_iocs, not_present_iocs

# function to check if a given list of critical paths is present in the system
def check_critical_paths(critical_paths):
    present_paths = []
    not_present_paths = []
    for path in critical_paths:
        if os.path.exists(path):
            present_paths.append(path)
        else:
            not_present_paths.append(path)
    return present_paths, not_present_paths

# list of critical paths for Windows
windows_critical_paths = [
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\"
]

# list of critical paths for Linux
linux_critical_paths = [
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/"
]

critical_paths = {
    "Windows": windows_critical_paths,
    "Linux": linux_critical_paths
}

try:
    # fetch IOC data from MISP API
    response = requests.post(misp_url, headers=headers, data=payload)
    ioc_list = response.json()["response"]["Attribute"]
    ioc_list = [ioc["value"] for ioc in ioc_list]
except Exception as error:
    print(f"Error while fetching data from MISP API: {error}")
    ioc_list = []

# create database connection and cursor
conn = sqlite3.connect("ioc_db.sqlite")
cursor = conn.cursor()

# create table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS ioc_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT
    type TEXT,
    category TEXT,
    time_checked TEXT
)
""")

# categorize the IOCs and insert them into the database
present_iocs, not_present_iocs = check_ioc_presence(ioc_list)
for ioc in present_iocs:
    cursor.execute("""
    INSERT INTO ioc_data (value, type, category, time_checked)
    VALUES (?, ?, ?, ?)
    """, (ioc, "ip", "present", str(time.time())))
for ioc in not_present_iocs:
    cursor.execute("""
    INSERT INTO ioc_data (value, type, category, time_checked)
    VALUES (?, ?, ?, ?)
    """, (ioc, "ip", "not_present", str(time.time())))

# check the critical paths and categorize them
os_type = platform.system()
critical_paths_list = critical_paths.get(os_type, [])
present_paths, not_present_paths = check_critical_paths(critical_paths_list)
for path in present_paths:
    cursor.execute("""
    INSERT INTO ioc_data (value, type, category, time_checked)
    VALUES (?, ?, ?, ?)
    """, (path, "path", "present", str(time.time())))
for path in not_present_paths:
    cursor.execute("""
    INSERT INTO ioc_data (value, type, category, time_checked)
    VALUES (?, ?, ?, ?)
    """, (path, "path", "not_present", str(time.time())))

conn.commit()
conn.close()

# Flask app to expose the stored data to the user
app = Flask(__name__)

@app.route("/iocs", methods=["GET"])
def get_iocs():
    conn = sqlite3.connect("ioc_db.sqlite")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT value, type, category, time_checked
    FROM ioc_data
    """)
    iocs = cursor.fetchall()

    conn.close()

    return jsonify(iocs)

@app.route("/iocs/search", methods=["GET"])
def search_iocs():
    query = request.args.get("q")

    if not query:
        return jsonify({"error": "Query parameter is required"}), 400

    conn = sqlite3.connect("ioc_db.sqlite")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT value, type, category, time_checked
    FROM ioc_data
    WHERE value LIKE ? OR category LIKE ?
    """, (f"%{query}%", f"%{query}%"))
    iocs = cursor.fetchall()

    conn.close()

    return jsonify(iocs)

if __name__ == "

# Run the app
if __name__ == "__main__":
    app.run(debug=True)

