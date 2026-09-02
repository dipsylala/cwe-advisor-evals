import sqlite3


def search_customers(term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # SAST FINDING: CWE-89 (SQL Injection) reported here. Sink is the next statement.
    cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
    return cursor.fetchall()
