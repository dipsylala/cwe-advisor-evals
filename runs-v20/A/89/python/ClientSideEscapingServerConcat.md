## Verdict

Confirmed. `search_customers()` builds a SQL statement by concatenating the raw `term` argument directly into the query string. The only quote-handling in this flow happens in the browser (`search.js`'s `term.replace(/'/g, "\\'")`), which is a client-side convenience that an attacker never has to go through — the `/api/search` endpoint can be called directly with any payload, and even if the escaped value did arrive, SQLite string literals are terminated by `'`, not by a backslash-escaped quote, so a payload like `x\' OR \'1\'=\'1` still closes the literal early. There is no server-side defense at the actual sink.

## Source

`term`, the parameter passed into `search_customers(term)` in `search.py`. It is attacker-controlled HTTP input (the value read from the `/api/search?term=...` query string that `search.js`'s `submitSearch()` sends), and it reaches the database with no server-side validation, escaping, or parameterization applied to it.

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

The fix replaces string concatenation with a parameterized query: the `?` placeholder tells `sqlite3` to send `term` to the database driver as a bound value rather than as text spliced into the SQL, so the driver treats it strictly as data no matter what characters it contains — quotes, comment sequences, or `OR`-style boolean payloads all lose their special meaning. This removes the vulnerability at the sink itself, which is what actually matters here, since the client-side `replace(/'/g, "\\'")` in `search.js` was never a real control: it runs in code the attacker fully controls (or can bypass by calling the endpoint directly), and it doesn't even match SQLite's escaping rules (SQLite escapes an embedded single quote by doubling it as `''`, not by prefixing it with a backslash), so it offered no protection even in the best case. No change to `search.js` is needed or made; it can keep its existing behavior since the security boundary now lives entirely on the server.
