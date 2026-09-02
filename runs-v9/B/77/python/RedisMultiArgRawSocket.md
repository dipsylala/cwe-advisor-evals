## Verdict

Exploitable. CWE-77 (Improper Neutralization of Special Elements used in a Command). Confidence: high.

## Source

`request["session_id"]` and `request["locale"]` in `update_session_preferences` (lines 7-8) - both are attacker-controlled fields of an inbound HTTP POST to `/session/preferences`, with no validation or encoding applied before use.

## Fix

Vulnerable code (line 10-13):

```python
conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
key = f"session:{session_id}"
# SAST FINDING: CWE-77 reported here. Sink is the next statement.
conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
response = conn.recv(1024)
conn.close()
return response
```

Fixed code:

```python
import redis


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    client = redis.Redis(
        host="127.0.0.1", port=6379,
        socket_connect_timeout=5, socket_timeout=5,
    )
    key = f"session:{session_id}"
    fields_added = client.hset(key, mapping={"theme": "dark", "locale": locale})
    return fields_added
```

Library recommendation: `redis` (redis-py). The loaded guidance names this client but does not carry a minimum safe version; confirm the resolved version against SCA/dependency-check tooling before merging - do not take a version number from this proposal.

## Explanation

The original code hand-builds a Redis inline-protocol command with an f-string and writes it directly to a raw socket. Both `session_id` (folded into `key`) and `locale` are interpolated straight into the command text, so a value containing `\r\n` terminates the `HSET` command early and lets the attacker append arbitrary further commands (e.g. `\r\nFLUSHALL\r\n`) that the Redis server will execute in sequence on the same connection. The fix replaces the raw socket and string-built command with redis-py's `hset()`, which sends each argument as its own length-prefixed RESP bulk string. Under that framing, embedded `\r\n` or Redis keywords inside `key` or `locale` are stored as literal argument bytes and cannot be parsed as a new command, closing the injection. `theme`/`locale` occupy field-name and field-value argument positions (never the command-name position), so the framing guarantee fully applies to both.

## Behaviour changes

- **Return value type**: the original returns the raw RESP-encoded bytes read from the socket (e.g. `b":2\r\n"`). The fixed code returns redis-py's parsed result of `hset()` - an `int` giving the number of new fields added by this call (fields that already existed and were merely updated are not counted). Any caller that parses the old raw byte response will need updating to consume the integer instead.
- **Connection lifecycle**: the original opens and explicitly closes one TCP socket per call. `redis.Redis()` instead manages a connection pool; the fixed code no longer closes a connection explicitly after each call. This is a resource-management difference, not a security regression, but it means a connection may be reused across calls rather than freshly opened each time.
- **Timeout parameter**: the original's `timeout=5` applied only to connection establishment (`socket.create_connection`). The fixed code sets both `socket_connect_timeout=5` (connect) and `socket_timeout=5` (read/write operations) to approximate the same bound; the latter is new and did not exist in the original, which had no read timeout on `conn.recv()`.
- No change to the command semantics themselves: the same key, and the same two hash fields (`theme` hardcoded to `dark`, `locale` from input), are written.
