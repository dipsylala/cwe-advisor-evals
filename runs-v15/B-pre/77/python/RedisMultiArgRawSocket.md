## Verdict

Confirmed. Untrusted input from `request["locale"]` is directly interpolated into a Redis inline protocol command string sent over a raw socket, allowing command injection via CRLF sequences.

## Source

Line 8: `locale = request["locale"]` — untrusted input from HTTP request

Line 13: `conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())` — directly concatenated into Redis command string and sent to the server

## Fix

Replace the raw socket code with redis-py's `redis.Redis` client and its `.hset()` method, which frames each argument separately so embedded delimiters cannot split the command:

```python
import redis


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = redis.Redis(host="127.0.0.1", port=6379, socket_connect_timeout=5, decode_responses=True)
    key = f"session:{session_id}"
    conn.hset(key, mapping={"theme": "dark", "locale": locale})
    conn.close()
```

## Explanation

The original code hand-builds a Redis inline protocol command by concatenating the locale value directly into an f-string. Redis reads the plain-text protocol line-by-line, so an embedded CRLF (`\r\n`) in the locale would terminate the current command and start a new one, allowing injection of arbitrary Redis operations.

The fix uses `redis.Redis` from the redis-py library to construct the command using the RESP (REdis Serialization Protocol) framing protocol instead. Each argument is encoded as a RESP bulk string with an explicit length prefix, which prevents embedded delimiters from being interpreted as command separators. The `.hset()` method encodes both the field names and the locale value as separate framed arguments, making injection impossible even if locale contains CRLF, spaces, or Redis command names.

## Behaviour changes

- **Return value**: `socket.recv()` is replaced with `.hset()`, which returns an integer (the number of fields that were added). The original code returned the raw socket response bytes; if the caller depends on parsing that response, it should be updated to check the integer return value instead.
- **Implicit parameters**: `socket.create_connection()` is replaced with `redis.Redis()`. The timeout parameter is now passed as `socket_connect_timeout` to maintain the 5-second connection timeout. The `decode_responses=True` flag decodes bytes to strings automatically, matching typical usage patterns.
- **Error handling**: Socket errors and protocol errors now raise `redis.ConnectionError` or `redis.RedisError` instead of socket exceptions. Calling code that catches `socket.error` should be updated to catch `redis.RedisError` or allow the exception to propagate for centralized error handling.
- **Dependency**: Requires `redis` library (redis-py). Verify the version supports the `.hset()` method with the `mapping` parameter (available in redis-py 2.10+, stable in all modern releases).
