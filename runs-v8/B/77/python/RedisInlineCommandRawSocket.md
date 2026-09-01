## Verdict

Exploitable command injection. An attacker can inject Redis commands by embedding newlines or command syntax in the `bio` parameter, since the vulnerable code hand-builds the inline protocol command using string interpolation without framing.

## Source

Line 8: `bio = request["bio"]` — untrusted user input.

The value flows directly into line 13 via the f-string interpolation without sanitization or parameterization.

## Fix

Replace the raw socket code with `redis.Redis` client and its parameterized `.set()` method:

```python
import redis

def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True, socket_connect_timeout=5)
    key = f"user:bio:{username}"
    result = r.set(key, bio)
    r.close()
    return result
```

## Explanation

The vulnerable code builds a raw Redis inline protocol command by interpolating `bio` directly into an f-string, then sends it via raw socket. In the Redis inline protocol, `\r\n` (and `\n`) are command terminators; an attacker who controls `bio` can inject embedded newlines to append arbitrary Redis commands (e.g., `bio = "value\r\nFLUSHALL"` would execute both SET and FLUSHALL).

The fix uses `redis.Redis` client methods, which use the RESP (REdis Serialization Protocol). RESP encodes each argument as a bulk string with an explicit length prefix, preventing embedded delimiters from being interpreted as command separators. The argument framing means `\r\n` inside a value is stored as literal data, not a command terminator.

## Behaviour changes

- **Return value:** Changes from raw bytes (from `conn.recv()`) to a boolean. The `.set()` method returns `True` on success. Code that depends on parsing the response bytes will need to be updated, but the typical case (just checking success/failure) maps cleanly.
- **Connection handling:** Switched from manual socket creation and closure to `redis.Redis` client lifecycle. The timeout is preserved via `socket_connect_timeout=5`.
- **Output encoding:** `decode_responses=True` ensures return values are strings rather than bytes, matching the intent of the original code.
- **Key construction:** Unchanged; `f"user:bio:{username}"` remains as a literal key name, not an injection point.
