## Verdict

- **cwe_id**: CWE-89
- **location**: CursorExecuteStringFormat.py, line 16 (`cursor.execute(query)`)
- **verdict**: exploitable
- **confidence**: high
- **assumptions**: none

## Source

`request.args.get("customer_id")` (line 9) - the Flask query-string parameter `customer_id`, fully attacker-controlled and unvalidated.

## Fix

**library_recommendation**: none - the fix uses `sqlite3`'s built-in parameterized query support (already imported), no new dependency required.

Vulnerable code:

```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
# SAST FINDING: CWE-89 ... Sink is the next statement.
cursor.execute(query)
```

Fixed code:

```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

## Explanation

`customer_id` flows from the Flask request's query string directly into an f-string that is concatenated into the SQL text, so a value such as `1 OR 1=1` or `1; DROP TABLE orders;--` becomes part of the query's structure rather than its data - classic CWE-89. The fix replaces the f-string interpolation with the driver's `?` placeholder and passes `customer_id` as a separate bound parameter via the second argument to `cursor.execute()`. `sqlite3` then transmits the value as data in all cases, including the unquoted numeric-looking position the original code left vulnerable, so it can no longer alter the query's logic regardless of its content.

## Behaviour changes

- The query text lost the literal customer_id value and now carries a `?` placeholder; the value is supplied via `cursor.execute()`'s second argument instead. This is the sink's normal parameterized-query calling convention, not a behavioural change to the returned rows.
- Previously, a non-numeric `customer_id` (e.g. `abc`) would raise a `sqlite3.OperationalError` at execution because it was interpolated unquoted into the SQL text; with a bound parameter, `sqlite3` instead compares the column against the literal string `"abc"`, which raises no error and simply returns zero rows (assuming `customer_id` is stored as an integer column). This is a byproduct of closing the injection and matches the sink's documented parameter-binding behavior; no other output, return value, or error path changes.
- All other logic (connection handling, `fetchall()`, response shape, `conn.close()`) is unchanged.
