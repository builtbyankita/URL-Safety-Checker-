
import sqlite3

def create_database():

    conn = sqlite3.connect("scan_history.db")

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            domain TEXT,
            risk_score INTEGER,
            status TEXT,
            scan_time TEXT
        )
    """)

    conn.commit()

    conn.close()

from datetime import datetime

def save_scan(url, domain, risk_score, status):

    conn = sqlite3.connect("scan_history.db")

    cursor = conn.cursor()

    scan_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    cursor.execute("""
        INSERT INTO scans
        (url, domain, risk_score, status, scan_time)
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        domain,
        risk_score,
        status,
        scan_time
    ))

    conn.commit()
    conn.close()

def get_scan_history():

    conn = sqlite3.connect("scan_history.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT url, domain, risk_score, status, scan_time
        FROM scans
        ORDER BY id DESC
    """)

    records = cursor.fetchall()

    conn.close()

    columns = [
        "Website URL",
        "Domain",
        "Risk Score",
        "Status",
        "Scan Date & Time"
    ]

    history = [
        dict(zip(columns, record))
        for record in records
    ]

    return history
