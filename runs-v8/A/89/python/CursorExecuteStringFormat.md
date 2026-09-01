## Verdict

**Confirmed SQL Injection vulnerability.** User-controlled input from `request.args.get("customer_id")` is directly interpolated into a SQL query via f-string formatting and executed without parameterization.

## Source

```python
customer_id = request.args.get("customer_id")
# ...
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
cursor.execute(query)
```

The vulnerability is on line 16: `cursor.execute(query)` executes a query constructed with unsanitized user input. An attacker can inject arbitrary SQL by crafting `customer_id` values like `1; DROP TABLE orders;--` or `1 UNION SELECT ...`.

## Fix

```python
@app.route("/orders")
def get_orders():
    customer_id = request.args.get("customer_id")

    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
    cursor.execute(query, (customer_id,))

    rows = cursor.fetchall()
    conn.close()

    return {"orders": rows}
```

Replace the f-string query with a parameterized query using the `?` placeholder, and pass the `customer_id` as a separate argument tuple to `cursor.execute()`.

## Explanation

SQL injection occurs when untrusted input is concatenated directly into SQL queries. The f-string on line 14 constructs the query before execution, allowing an attacker to control the SQL syntax itself.

Parameterized queries (prepared statements) solve this by separating SQL structure from data. The database driver automatically escapes the parameter value and treats it as data, never as executable SQL. SQLite3's `cursor.execute(query, parameters)` form enforces this separation: the query string contains placeholders (`?`), and parameters are passed separately as a tuple. This guarantees the parameter cannot alter the query's logic, regardless of its content.
