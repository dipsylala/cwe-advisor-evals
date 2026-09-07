## Verdict

Exploitable. An attacker can inject arbitrary Redis commands by embedding `\r\n` (CRLF) sequences in the bio field. For example, a bio value of `test\r\nFLUSHALL\r\n` would be interpreted as two separate commands: `SET user:bio:username test` and `FLUSHALL`, causing data loss.

## Source

Untrusted input: `bio = request["bio"]` (line 5) - user-supplied profile biography text with no validation or sanitization.

## Fix

**Vulnerable code (line 13):**
```python
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

**Fixed code:**
```python
import redis

def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    client = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True, socket_connect_timeout=5)
    key = f"user:bio:{username}"
    client.set(key, bio)
    client.close()
    return "OK"
```

## Explanation

The original code hand-builds a Redis command by string interpolation, treating the bio value as literal text and concatenating it directly into the command string. When sent via the raw inline protocol, embedded CRLF sequences in the bio are interpreted as command delimiters, allowing the attacker to inject additional commands. The fixed code uses the redis-py library's `Redis` client and its `.set()` method, which encodes each argument as a RESP bulk string with an explicit length prefix. This framing prevents embedded delimiters from being interpreted as separate commands—the bio value, regardless of its content, is always treated as a single opaque argument value.

## Behaviour changes

- **Connection type**: Changed from raw socket (`socket.create_connection()`) to redis-py's `Redis` client. The client manages the connection pool and lifecycle internally.
- **Protocol encoding**: Switched from Redis inline protocol (plain text with CRLF delimiters) to RESP (Redis Serialization Protocol), which uses length prefixes to delimit arguments and prevents delimiter injection.
- **Response handling**: The original code read a single response buffer; the fixed code delegates response parsing to the redis-py client, which handles pipelining and error responses automatically.
- **Return value**: Changed from raw socket response bytes to the redis-py library's return value (a string "OK" on success, or an exception on failure). The caller's error handling should now catch `redis.exceptions.RedisError` or its subclasses instead of checking response bytes.
- **Library dependency**: Requires the `redis` package. The minimum safe version is not specified in the loaded guidance; confirm the resolved version against SCA tooling before merging.
