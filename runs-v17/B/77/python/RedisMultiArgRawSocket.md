## Verdict
exploitable

## Source
`request["locale"]` (line 8) — untrusted dictionary value from the HTTP request

## Fix

### File: RedisMultiArgRawSocket.py

```python
import redis


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True, socket_connect_timeout=5)
    key = f"session:{session_id}"
    r.hset(key, mapping={"theme": "dark", "locale": locale})
    r.close()
```

## Explanation
The original code builds a Redis command by hand-concatenating user input into an f-string, then sends it over a raw socket using the inline protocol. This allows an attacker to inject `\r\n` sequences to terminate the current command and start a new one — for example, setting `locale` to `"\r\nFLUSHALL\r\n"` executes both the HSET and a destructive FLUSHALL. The fix replaces the raw socket connection with `redis.Redis` (redis-py), which uses the RESP protocol with explicit length-prefixed argument encoding. Each argument (`session_id`, `locale`) is passed separately to the `hset()` method, so embedded delimiters are encoded as literal data and cannot split into a second command. The `decode_responses=True` parameter mirrors the original code's intent to work with text.

## Behaviour changes
**Connection lifecycle**: The original code manually creates, uses, and closes a socket; the fixed code uses a `redis.Redis` client object which manages its own connection pool. Setting `socket_connect_timeout=5` on the client preserves the original 5-second timeout behavior. The fixed code calls `r.close()` to release the connection, preserving the original cleanup pattern.

**Return value**: The original code returns the raw bytes from `conn.recv(1024)`; the fixed code does not capture or return a response. This is a behaviour change: callers relying on the return value will get `None`. If response handling is required, the fix should capture `r.hset(...)` (which returns an integer count of fields added) or a subsequent Redis read operation and return that instead.

**Error handling**: The original code raises socket exceptions on connection failure; `redis.Redis` may raise `redis.ConnectionError` instead. The exception type differs but the semantic (connection failure propagates) is preserved.

**Dependencies**: The fix requires the `redis` package (redis-py) to be installed. The guidance names no minimum version; check against SCA/dependency-check tooling before merging.
