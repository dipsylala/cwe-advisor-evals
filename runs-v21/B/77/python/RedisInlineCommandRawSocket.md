## Verdict

exploitable

## Source

Untrusted input from `request["username"]` and `request["bio"]` flows into the Redis command string without sanitization.

## Fix

### File: RedisInlineCommandRawSocket.py

```python
import redis


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    client = redis.Redis(
        host="127.0.0.1",
        port=6379,
        decode_responses=True,
        socket_connect_timeout=5
    )
    key = f"user:bio:{username}"
    response = client.set(key, bio)
    client.close()
    return response
```

## Explanation

The original code builds a Redis command string using f-string interpolation and sends it over a raw socket using the plain-text inline protocol, which uses CRLF (`\r\n`) as a command delimiter. An attacker can inject Redis commands by embedding `\r\n` in either `username` or `bio`, causing the server to parse the payload as multiple commands (for example, `FLUSHALL`, `DEL`, or other Redis operations).

The fix replaces the raw socket and hand-built command with `redis.Redis` (the redis-py client library). This library encodes each argument as a RESP bulk string with an explicit length prefix, so embedded newlines and Redis command syntax in the data are treated as literal bytes rather than command delimiters or separators. The key and value are passed as separate arguments to `.set()`, ensuring they cannot be interpreted as commands or command boundaries.

## Behaviour changes

1. **Return value**: The original code returns raw response bytes from `conn.recv(1024)` (typically `b'+OK\r\n'` on success). The fixed code returns the boolean result of `client.set()` (True on success, None or False on failure). This is a clearer, more Pythonic signal. Callers that depend on parsing the raw Redis response byte string will need to adjust.

2. **Error handling**: The original code will not raise on network errors until a `recv()` attempt; the redis-py client raises immediately on connection failure or protocol errors. Callers should wrap the function in try-except for `redis.ConnectionError` or `redis.RedisError` as appropriate.

3. **Timeout semantics**: The original `socket_connect_timeout=5` is a connection-only timeout. Redis client timeouts apply to individual operations; a single `.set()` call has a default socket timeout of 0 (blocking). If stricter timeouts are needed, pass `socket_timeout` to the `Redis()` constructor.
