## Verdict

Real vulnerability. The `username` and `bio` parameters from the request are interpolated directly into a Redis inline protocol command string and sent over a raw socket. An attacker who controls either value can embed Redis protocol delimiters (CRLF, spaces, command names) to execute arbitrary commands—for example, `bio = "value\r\nFLUSHALL\r\n"` to flush all keys, or `bio = "value\r\nDEL user:bio:*\r\n"` to delete matching keys. The inline protocol parses each CRLF-terminated line as a separate command, so the injected text becomes an executable command rather than literal data.

## Source

**File:** `RedisInlineCommandRawSocket.py`  
**Lines:** 7–8 (source), 11–13 (sink)

- **Source:** `username` and `bio` from the untrusted `request` dict (lines 7–8)
- **Data flow:** Both are interpolated into the f-string at line 11 (key) and line 13 (command), passed to the socket at line 13
- **Sink:** `conn.sendall()` at line 13 with the hand-built protocol command string

The vulnerability occurs because the raw socket protocol (Redis inline format) uses CRLF (`\r\n`) as a command terminator, so an embedded newline in either `username` or `bio` splits the command into separate tokens that Redis interprets as separate commands.

## Fix

### File: RedisInlineCommandRawSocket.py

```python
import redis


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    # Use redis-py client with parameterized command API instead of raw socket.
    # Each argument is framed separately by the RESP protocol, so embedded
    # delimiters cannot split into separate commands.
    conn = redis.Redis(host="127.0.0.1", port=6379, socket_connect_timeout=5)
    key = f"user:bio:{username}"
    response = conn.set(key, bio)
    conn.close()
    return response
```

## Explanation

The fix replaces the raw socket connection and hand-built Redis inline protocol command with the `redis-py` client library (`redis.Redis`). The `redis-py` library encodes each command argument as a RESP (Redis Serialization Protocol) bulk string with an explicit length prefix, rather than relying on delimiters to separate fields. When `conn.set(key, bio)` is called, the key and value are passed as separate typed arguments to the RESP encoder, so embedded CRLF, spaces, and Redis command keywords in `username` or `bio` are stored as literal bytes and cannot be misinterpreted as protocol delimiters or separate commands. This eliminates the command injection vector.

The inline protocol string is never constructed, so there is no way for an attacker to inject protocol delimiters. The `redis-py` library handles all protocol framing and encoding internally, matching the principle that untrusted input should never be hand-built into a command string.

## Behaviour changes

- **Return value:** The original code returned raw socket response bytes (`bytes`); the fixed code returns the result from `redis.Redis.set()`, which is `True` on success or `False` if the operation fails (depending on Redis server response). Callers relying on the raw protocol bytes will need to adjust.
- **Error handling:** The original code would raise `socket.error` or `socket.timeout`; the fixed code raises `redis.ConnectionError`, `redis.ResponseError`, or other redis-py exceptions. Callers that catch specific socket exceptions will need to be updated.
- **Connection timeout:** The original code used `socket.create_connection(..., timeout=5)` which only applies to the connection phase; the fixed code uses `socket_connect_timeout=5` in the Redis constructor, which is equivalent for the connection phase. Per-command timeouts are not set, so long-running operations will block indefinitely (matching the original behaviour).
- **Dependency:** The fixed code requires the `redis` package (redis-py library) to be installed. This can be added via `pip install redis`.

The fix is a breaking change in return type and exception class, but it is necessary to close the injection vulnerability and is justified by the switch to parameterized command construction.
