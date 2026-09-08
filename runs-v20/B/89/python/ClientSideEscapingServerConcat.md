## Verdict

Confirmed - CWE-89 SQL Injection. Real, exploitable.

## Source

`term`, the parameter passed into `search_customers(term)` in `search.py`. It originates as attacker-controlled request input (the call chain's `search.js` sends it as a `term` query parameter to a `/api/search` endpoint that presumably invokes `search_customers`). The client-side code in `search.js` runs `term.replace(/'/g, "\\'")` before sending the value, but this is a client-side transformation only: an attacker calls the server endpoint directly, bypassing the browser and this replace entirely, so it provides no protection. Even taken at face value, backslash-escaping a quote is not a valid SQLite escape sequence (SQLite escapes an embedded `'` by doubling it to `''`, not by prefixing `\`), so the transformation would not neutralize the injection even if it were enforced server-side. The value reaching `search_customers` must be treated as fully untrusted.

## Fix

### File: search.py
```python
import sqlite3


def search_customers(term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
    return cursor.fetchall()
```

## Explanation

The sink at line 9 builds the SQL statement by concatenating `term` directly into a single-quoted string literal: `"SELECT id, name FROM customers WHERE name = '" + term + "'"`. A value such as `x' OR '1'='1` closes the literal early and appends attacker-controlled query logic, returning every row in the table regardless of the intended filter. The fix replaces string concatenation with `sqlite3`'s parameterized query form: the SQL text uses a `?` placeholder in place of the interpolated value, and `term` is passed as a separate element of the tuple argument to `cursor.execute()`. With this form, the SQLite driver sends the value to the database as data bound to the placeholder, never as part of the SQL text, so it cannot alter the query's structure no matter what characters it contains. This closes the injection independent of the client-side escaping in `search.js`, which remains irrelevant to server-side safety (and was never a correct escape for this context to begin with).

Sink contract preserved: `cursor.execute()` still returns the cursor object (unused, as before), `fetchall()` still returns the same shape of result set (a list of `(id, name)` tuples) for legitimate input, and failure behavior is unchanged - a malformed or absent `app.db` still raises the same `sqlite3` exceptions it did before. No arguments were added, removed, or defaulted differently; the only change is how the untrusted value reaches the query engine.

**Check - names introduced:** The only new construct is passing a second positional argument, `(term,)`, to `cursor.execute()`. This is the standard `sqlite3.Cursor.execute(sql, parameters)` two-argument form from Python's standard-library `sqlite3` module, the same object already in use in the original code (`conn.cursor()` / `cursor.execute()`), so no new import or unverified API is introduced.

**Check - verification performed:** The fixed file was copied to a scratch location (outside the repository) and checked with `python -m py_compile`, which succeeded with no diagnostics. It was then exercised against a real in-memory `sqlite3` database seeded with two rows: the payload `x' OR '1'='1` against the original concatenation logic returned both rows (confirming the exploit), the same payload against the parameterized fix returned an empty result (no match, as expected for a literal name lookup), and a legitimate term (`alice`) against the fix returned the correct single matching row - confirming the fix closes the injection without breaking normal lookups.

## Behaviour changes

- Table b for evals

  | Row(s) affected | Old behaviour | New behaviour | Why |
  |---|---|---|---|
  | Input containing a `'` (including any SQL metacharacter payload) | Interpreted as part of the SQL statement; could alter query logic (e.g. return all rows, or in principle be extended to run additional statements/logic depending on the wrapping application) | Interpreted strictly as the literal value of `name` to match; a quote character is just a character in the search string, not a query terminator | Value is now bound as a parameter (`?`) rather than concatenated into the SQL text, so it can no longer change query structure |
  | Legitimate search terms (no metacharacters) | Exact-match lookup on `name` | Unchanged - identical exact-match lookup, identical result shape (`[(id, name), ...]`) | Parameterization does not alter the query's semantics for well-formed input, only how the value is transmitted to the driver |
