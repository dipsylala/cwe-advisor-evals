## Verdict

exploitable (confidence: high)

- **CWE**: CWE-90 (Improper Neutralization of Special Elements used in an LDAP Query - LDAP Injection)
- **Location**: `LdapFilterConcat.py`, line 20 (`conn.search(...)`), filter built at line 17

## Source

- **Source**: `request.args.get("username", "")` (line 12) - the Flask `username` query-string parameter, fully attacker-controlled, no default fallback that removes taint (defaults to `""` only when absent).
- **Flow**: `username` is concatenated directly into `search_filter = "(uid=" + username + ")"` (line 17) with no escaping, validation, or allowlist check between source and sink.
- **Sink**: `conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])` (line 20, `ldap3.Connection.search`). Because `username` is interpolated raw, an attacker can inject `*` to turn the equality test into a presence/wildcard match, or `)(` sequences to close the `(uid=...)` term and append additional filter clauses (e.g. `*)(|(uid=*)` to enumerate all directory entries via the same code path).
- **Sink contract**: `Connection.search()` returns a bool indicating success (unused by this code) and populates `conn.entries` / `conn.result` as a side effect; `search_scope` and `dereference_aliases` are left at their `ldap3` defaults (`SUBTREE` and `DEREF_ALWAYS` respectively) and are not part of this fix.

## Fix

Vulnerable code (lines 12-20):

```python
username = request.args.get("username", "")

server = Server(LDAP_SERVER, get_info=ALL)
conn = Connection(server, auto_bind=True)

search_filter = "(uid=" + username + ")"

# SAST FINDING: CWE-90 ... Sink is the next statement.
conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

Fixed code:

```python
from ldap3.utils.conv import escape_filter_chars

username = request.args.get("username", "")

server = Server(LDAP_SERVER, get_info=ALL)
conn = Connection(server, auto_bind=True)

safe_username = escape_filter_chars(username)
search_filter = "(uid=" + safe_username + ")"

conn.search(BASE_DN, search_filter, attributes=["cn", "mail", "uid"])
```

(Add the `from ldap3.utils.conv import escape_filter_chars` import alongside the existing `ldap3` import at the top of the file.)

## Explanation

`escape_filter_chars()` is `ldap3`'s RFC 4515 filter-escaping function: it converts each LDAP filter metacharacter in the input (`*`, `(`, `)`, backslash, and NUL) to its `\XX` hex-escaped form before the value is interpolated into `search_filter`. This keeps `username` confined to the value position of the `(uid=...)` equality term - an attacker-supplied `*`, `(`, or `)` is rendered as a literal character in the filter grammar rather than as filter syntax, so the injected value can no longer widen the match to a wildcard/presence test or close the term to splice in additional clauses (e.g. an `objectClass=*` disjunction). The fix only changes how the value is encoded before concatenation; the base DN, attribute list, and query construction otherwise stay identical, so it directly closes the CWE-90 finding at the point of concatenation without altering the search's structure.

## Behaviour changes

- The only functional difference for a legitimate `username` (alphanumeric, no LDAP metacharacters) is none - `escape_filter_chars()` is a no-op on such input, so ordinary lookups behave identically.
- For a `username` containing an LDAP metacharacter (`*`, `(`, `)`, `\`, or NUL), the escaped filter now looks for that character literally in the `uid` attribute instead of treating it as filter syntax; such lookups will typically return no match (404) where the unescaped version might previously have matched unintended entries or thrown a filter-parse error. This is the intended effect of closing the injection and is not a behaviour change beyond what the weakness itself required.
- No other arguments, return values, or control flow were altered: `search_scope`, `dereference_aliases`, and the requested `attributes` list are untouched, and the function's success/error handling (`entries` empty -> 404) is unchanged.
