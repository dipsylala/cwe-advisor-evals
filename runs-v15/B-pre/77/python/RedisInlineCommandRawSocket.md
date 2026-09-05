## Verdict

**VULNERABLE.** The code constructs a raw Redis inline protocol command by string interpolation without sanitization. An attacker controlling `username` or `bio` can inject CRLF sequences to execute arbitrary Redis commands.

## Source

Lines 10-13 open a raw socket and hand-build a Redis command string:

```python
conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
key = f"user:bio:{username}"
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

The `username` and `bio` values from the untrusted `request` dict are interpolated directly into the command string. A value like `username = "user\r\nFLUSHALL\r\n"` would make `key = "user:bio:user\r\nFLUSHALL\r\n"`, sending two commands to Redis: `SET user:bio:user:bio:user...` and then `FLUSHALL`.

## Fix

Replace the raw socket and string-building approach with redis-py's parameterized client API:

```python
import redis

def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    # Validate inputs as defence-in-depth
    if not username or len(username) > 255 or not all(c.isalnum() or c in "_-." for c in username):
        raise ValueError("Invalid username")
    if not bio or len(bio) > 10000:
        raise ValueError("Invalid bio")

    # Use redis-py parameterized API
    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True, socket_connect_timeout=5)
    key = f"user:bio:{username}"
    r.set(key, bio)
    return "OK"
```

## Explanation

The redis-py client library uses the RESP (Redis Serialization Protocol) to send commands. Each argument is encoded as a bulk string with an explicit length prefix, so embedded delimiters like `\r\n` in the value cannot be interpreted as command separators. The value becomes literal data, not a new command boundary.

Key points:
- `.set(key, value)` passes the key and value as separate framed arguments, not as whitespace-delimited tokens in a raw command string.
- Input validation (allowlisting username characters, bounding lengths) provides defence-in-depth; even if a bypass existed in the client library, the constrained input would not execute new commands.
- The redis-py client manages connection pooling and timeouts internally; explicit socket handling is not needed.

## Behaviour changes

- **External behaviour**: Identical. The same data is stored in Redis under the same key and retrieved the same way.
- **Performance**: Negligible. redis-py's connection pooling and protocol handling are efficient; the socket overhead is replaced by a higher-level API.
- **Dependencies**: Requires `redis` package (e.g. `pip install redis`). The existing `socket` import is no longer needed.
- **Error handling**: redis-py raises `redis.ConnectionError` or `redis.ResponseError` on failure instead of relying on raw socket exceptions. Callers should handle these as appropriate.
