## Verdict

EXPLOITABLE. The code directly interpolates the untrusted `bio` parameter into a Redis command string sent via raw socket. A `bio` value containing `\r\n` followed by a Redis command name (e.g., `\r\nFLUSHALL\r\n`) would be parsed by the Redis server as two separate commands: one SET and one FLUSHALL.

## Source

Line 8: `bio = request["bio"]` — untrusted input from the HTTP request.

## Fix

Replace the raw socket code with `redis.Redis` client and its parameterized `.set()` method:

```python
import redis

def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
    key = f"user:bio:{username}"
    r.set(key, bio)
    r.close()
    return "OK"
```

## Explanation

The original code builds a Redis inline-protocol command by concatenating the `bio` value directly into a text string, then sends it via raw socket. The inline protocol is line-based: each command ends with `\r\n`, so an embedded CRLF in `bio` causes the server to read it as the end of the SET command and the start of a new command. The redis-py client library encodes each argument (including `bio`) as a RESP bulk string with an explicit length prefix, ensuring that delimiters embedded in the value are treated as literal data rather than parsed as command structure. This removes the injection vector while preserving the intended SET operation.

## Behaviour changes

- **Connection**: Switches from manual `socket.create_connection()` to redis-py's connection management. The connection pool is reused across calls if the client is kept as a module-level singleton (recommended for production).
- **Response handling**: `r.set()` returns a boolean (True on success) rather than raw bytes from `recv()`. Adjust callers accordingly.
- **Error handling**: redis-py raises `redis.exceptions.RedisError` subclasses (e.g., `ConnectionError`, `ResponseError`) instead of socket exceptions.
- **Return value**: Changed from raw server response bytes to a string status ("OK") to match redis-py convention.
