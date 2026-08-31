from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/orders")
def get_orders():
    customer_id = request.args.get("customer_id")

    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
    # SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()

    return {"orders": rows}
