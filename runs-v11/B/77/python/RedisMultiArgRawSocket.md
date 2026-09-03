## Verdict

Exploitable. The untrusted `locale` value from the request is directly interpolated into a Redis inline protocol command string. An attacker can inject CRLF characters to terminate the current command and start a new one, executing arbitrary Redis commands.

## Source

`request["locale"]` (line 8) - untrusted input from the request parameter dictionary

## Fix

**Vulnerable code (line 13):**
```python
conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
```

**Fixed code:**
```python
import redis

def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    client = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
    key = f"session:{session_id}"
    # Safe: each argument passed separately to .hset(), not concatenated into a command string
    response = client.hset(key, mapping={"theme": "dark", "locale": locale})
    return response
```

## Explanation

The original code builds a Redis inline protocol command by string interpolation, treating untrusted `locale` as raw text. Redis's inline protocol uses CRLF as a command terminator, so a payload like `dark\r\nFLUSHALL` would execute two commands: the intended HSET and an injected FLUSHALL. The fix uses redis-py's `Redis.hset()` method, which encodes each argument as a RESP bulk string with an explicit length prefix. This binary-safe encoding ensures that CRLF, spaces, and Redis command keywords in the value are treated as literal data, not command delimiters or separators. The untrusted value is now safely isolated from the command structure.

## Behaviour changes

1. **Return value type**: Original returns raw bytes (`conn.recv(1024)` response); fixed version returns an integer (count of fields added by `.hset()`). Callers expecting bytes will need to be updated.
2. **Connection handling**: Original uses manual socket lifecycle (`socket.create_connection()`, `conn.close()`); fixed version uses redis.Redis client which manages connections internally. This is simpler and safer but changes the connection model.
3. **Protocol change**: Original uses Redis inline protocol (text-based); fixed version uses RESP protocol (binary-safe). Both are valid Redis protocols; RESP is industry standard for client libraries.
