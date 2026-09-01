## Verdict

The finding is **confirmed**. Line 13 constructs a Redis inline-protocol command by string interpolation of untrusted `locale` input. If the value contains `\r\n`, it will be parsed by the Redis server as a command separator, allowing injection of arbitrary commands.

## Source

User-controlled `locale` from `request["locale"]` (line 8) is interpolated directly into a Redis command string without encoding or framing.

## Fix

Replace the raw socket and hand-built command string with redis-py's client API, which encodes each argument with an explicit length prefix so embedded delimiters cannot be interpreted as command separators.

**Fixed code:**

```python
import redis

def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=False)
    key = f"session:{session_id}"
    
    # Use hset() with separate arguments - redis-py encodes each as a RESP bulk string
    r.hset(key, mapping={"theme": "dark", "locale": locale})
    r.close()
```

## Explanation

The original code hand-builds a Redis command using string interpolation, then sends it as raw text on a socket. The Redis inline protocol is line-delimited, so an untrusted value containing `\r\n` will be parsed as separate commands. The fix uses `redis.Redis.hset()` with the client library's parameterized API, which encodes each argument—including `locale`—as a RESP bulk string with an explicit length prefix. This framing prevents embedded delimiters from being interpreted as command separators. The command name (`HSET`) and structure remain literals under application control; only the `theme` and `locale` values reach the server as data arguments.

## Behaviour changes

- The socket connection is replaced with redis-py's connection pool and client.
- Response handling changes: `redis-py` returns the result directly (number of fields added), eliminating the need for raw socket `recv()` and decoding.
- Connection lifecycle is managed by the library instead of explicit `close()`.
- The `session_id` is still used to construct the key name (`f"session:{session_id}"`); it is not isolated in a separate argument. To fully constrain command injection risk, `session_id` should also be validated (for example, restricted to alphanumeric characters and underscores) as defence-in-depth, though the redis-py framing already prevents it from escaping the key position.
