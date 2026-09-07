## Verdict

**CONFIRMED** – CWE-77 command injection via untrusted input in hand-built Redis protocol command.

## Source

Line 13, `conn.sendall()` sink. Untrusted values from `request["locale"]` and `request["session_id"]` reach the sink through string concatenation in the f-string on line 13.

## Fix

Replace raw socket communication and manual command string building with `redis-py`'s client API, passing each argument as a separate parameter:

```python
import redis

def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
    key = f"session:{session_id}"
    # redis-py's .hset() method passes each argument as a separately framed RESP value
    r.hset(key, mapping={"theme": "dark", "locale": locale})
    return {"status": "ok"}
```

## Explanation

The original code hand-builds a Redis inline protocol command string (`f"HSET {key} theme dark locale {locale}\r\n"`) and sends it via raw socket. Redis interprets embedded `\r\n` sequences as command terminators; a value like `locale="en\r\nFLUSHALL"` would inject and execute a second command.

The fix uses `redis.Redis()` from redis-py, which encodes each argument as a RESP (Redis Serialization Protocol) bulk string with an explicit length prefix. This framing prevents newlines and delimiters in argument values from being interpreted as command boundaries. The parameterized `.hset(key, mapping=...)` call ensures `locale` is passed as a separate argument, not concatenated into a command string.

This satisfies the CWE-77 remediation guidance: use the target interpreter's (Redis in this case) structured command-construction API instead of building command strings by concatenation.

## Behaviour changes

- **Removed**: raw socket communication via `socket.create_connection()` and `conn.sendall()`
- **Added**: `redis.Redis()` client instantiation
- **Return value**: changed from a raw bytes response to a structured return (shown as `{"status": "ok"}`; the actual return depends on caller requirements, but `r.hset()` returns the number of fields added)
- **Assumption**: redis-py is available as a dependency; it is the standard, widely-maintained Redis client library for Python
