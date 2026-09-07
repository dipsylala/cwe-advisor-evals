## Verdict

Confirmed CWE-77 (Improper Neutralization of Special Elements used in a Command - Command Injection) via Redis inline protocol.

**Source:** `request["bio"]` and `request["username"]` (untrusted user input from HTTP request)

**Sink:** `conn.sendall(f"SET {key} {bio}\r\n".encode())` at line 13

**Data flow:** The username and bio values from the request are interpolated directly into a manually-constructed Redis inline protocol command string, then sent over a raw socket without any framing or parameterization.

**Exploitability:** An attacker can inject a newline character (CRLF: `\r\n`) into the bio value to terminate the SET command early and inject additional Redis commands. For example, `bio = "value\r\nFLUSHALL\r\n"` would cause the server to execute FLUSHALL after storing the bio, deleting all keys in the Redis database. The inline protocol interprets each line as a separate command, enabling arbitrary command execution.

## Source

Line 13 in the vulnerable file:
```python
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

The key and bio values originate from untrusted request input and are interpolated into the command string without any neutralization of Redis protocol delimiters.

## Fix

### File: RedisInlineCommandRawSocket.py

```python
import redis


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    # Validate inputs as defence-in-depth
    if not username or not isinstance(username, str) or len(username) > 255:
        raise ValueError("Invalid username")
    if not isinstance(bio, str) or len(bio) > 10000:
        raise ValueError("Invalid bio")

    # Use redis-py client instead of raw socket with inline protocol
    r = redis.Redis(host="127.0.0.1", port=6379, socket_connect_timeout=5, decode_responses=True)
    key = f"user:bio:{username}"
    # Each argument is passed separately via .set(), preventing injection via CRLF or delimiters
    r.set(key, bio)
    response = r.get(key)
    r.close()
    return response
```

## Explanation

The fix replaces the vulnerable raw socket implementation with redis-py's `redis.Redis` client library, which uses the RESP (Redis Serialization Protocol) to frame each argument. Unlike the inline protocol (which is line-delimited and subject to CRLF injection), RESP encodes each argument with an explicit length prefix as a bulk string. This means an untrusted value containing `\r\n`, spaces, or command names cannot be interpreted as a separate command when passed as an argument to `.set()`.

The `.set(key, bio)` method internally frames both the key and bio as separate RESP bulk strings, so embedded delimiters are treated as literal data. An attacker's injected newline becomes part of the data payload, not a command separator.

Defence-in-depth validation is added to constrain input length and type, complementing the library's protocol-level protection. The connection timeout is preserved using the `socket_connect_timeout` parameter.

## Behaviour changes

- **Library change:** Raw `socket` module replaced with `redis` (redis-py)
- **API change:** Manual string building with `sendall()` replaced with `.set(key, value)` and `.get(key)` methods
- **Protocol change:** Inline protocol replaced with RESP framing (transparent to application logic)
- **Response handling:** Changed from raw bytes via `recv()` to decoded strings via `.get()` (due to `decode_responses=True`)
- **Validation:** New input validation raises `ValueError` for invalid username or bio, replacing silent-accept-all behavior
- **Resource management:** `.close()` called on Redis client instead of socket to properly clean up connection

The fix preserves application intent: a user bio is stored in Redis and retrieved. The legitimate bio value still works identically, but injected commands are now treated as literal data and stored as part of the value rather than executed.

Python syntax verification: `python -m py_compile` passed on the fixed code.
