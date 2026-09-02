## Verdict

exploitable (confidence: high)

- cwe_id: CWE-89
- location: CursorExecuteStringFormat.py, line 16 (`cursor.execute(query)`), built at line 14

## Source

`customer_id = request.args.get("customer_id")` (line 9) - an unvalidated Flask query-string parameter, fully attacker-controlled, reaches the sink with no intervening validation, type coercion, or allowlist check. It flows directly into an f-string (`query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"`, line 14) that is passed unchanged to `cursor.execute(query)` (line 16). A request such as `/orders?customer_id=1 OR 1=1` or `/orders?customer_id=1; DROP TABLE orders;--` is interpolated verbatim into the query text, letting an attacker alter the WHERE clause or chain additional statements.

Sink contract: `cursor.execute()` returns `None` and mutates `cursor` in place; the caller reads results separately via `cursor.fetchall()` (line 18). On a malformed query it raises `sqlite3.OperationalError`, which is unhandled here and would propagate as a 500 response.

## Fix

No third-party library is needed; `sqlite3` (standard library) already supports parameterized queries via `?` placeholders.

Vulnerable code:

```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
# SAST FINDING: CWE-89 reported here. Sink is the next statement.
cursor.execute(query)
```

Fixed code:

```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

## Explanation

The fix replaces f-string interpolation of `customer_id` with a static SQL string containing a `?` placeholder, and passes `customer_id` as a separate parameter in a tuple to `cursor.execute()`. `sqlite3`'s DB-API driver sends the query text and the value to the database separately, so the value is always bound as literal data and can never change the query's structure - the same technique the general and Python-specific CWE-89 guidance both prescribe as the primary defence, in place of manual escaping or blocklisting, which the guidance flags as unreliable for this exact unquoted-numeric-context case (`customer_id = 1 OR 1=1`).

## Behaviour changes

- If `customer_id` is absent, `request.args.get("customer_id")` returns `None`. Original code: `None` is interpolated as the literal text `customer_id = None`, which is invalid SQL and raises `sqlite3.OperationalError` (surfacing as an unhandled 500). Fixed code: `None` is bound as SQL `NULL`, so `customer_id = NULL` evaluates to unknown/false and the query succeeds, returning `{"orders": []}` instead of erroring. This is a byproduct of correct parameter binding, not a new omission - if the endpoint requires `customer_id` to be present, that should be enforced with an explicit check before the query, independent of this fix.
- No other differences: return value, columns selected, row shape, and control flow are unchanged from the original sink contract.
