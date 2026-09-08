## Verdict

Confirmed. `username` and `bio` are attacker-controlled request fields that are formatted directly into a Redis *inline command* string sent over a raw TCP socket. Redis's inline protocol terminates a command on `\r\n`, so either field can inject additional Redis commands.

## Source

`request["username"]` and `request["bio"]` in `update_profile_bio` (lines 7-8) — both taken unvalidated from an HTTP request handler's input dict.

## Fix

### File: RedisInlineCommandRawSocket.py
```python
import redis

_redis_client = redis.Redis(host="127.0.0.1", port=6379, socket_timeout=5)


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    key = f"user:bio:{username}"
    return _redis_client.set(key, bio)
```

## Explanation

The original code builds the Redis command as a plain text line, `f"SET {key} {bio}\r\n"`, and writes it straight onto the socket. Redis's inline-command protocol has no length-prefixing or escaping for that form — it simply splits the line on whitespace and treats `\r\n` as the end of the command. Because `bio` (and `username`, via `key`) is concatenated into that line unescaped, an attacker who controls either value can embed a `\r\n` followed by any additional Redis command: for example a `bio` value of `"hi\r\nFLUSHALL\r\nSET pwn 1"` closes the intended `SET` early and runs `FLUSHALL` and a second `SET` with attacker-chosen key/value, and the same technique reaches commands like `CONFIG SET` or `EVAL` depending on what the deployment exposes. A value with an embedded space also silently corrupts the key/value split even without a full injection.

The fix replaces the hand-rolled inline-protocol socket code with the `redis` client library (RESP protocol), which sends each command as a length-prefixed array of bulk strings. Because each argument is transmitted with an explicit byte length rather than delimited by whitespace or `\r\n`, no sequence of bytes inside `key` or `bio` can terminate the argument early or introduce a second command — the value is treated as opaque data regardless of its content, so no escaping or allowlisting of `username`/`bio` is needed to close this class of injection. `redis-py` is the actively maintained, standard Python Redis client; a dependency/version check should confirm the installed release has no open advisories before deployment.
