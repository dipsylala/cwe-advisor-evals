## Verdict

exploitable

- cwe_id: CWE-77
- location: RedisInlineCommandRawSocket.py, line 13 (`conn.sendall(...)`)
- confidence: high

## Source

`request["username"]` and `request["bio"]` (lines 7-8) are read directly from the incoming request with no validation. Both flow unmodified into the command string built on line 13: `username` via the `key` variable (line 11), `bio` directly.

## Fix

### File: RedisInlineCommandRawSocket.py

```python
import redis


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    client = redis.Redis(host="127.0.0.1", port=6379, socket_timeout=5)
    key = f"user:bio:{username}"
    try:
        client.set(key, bio)
        response = b"+OK\r\n"
    except redis.RedisError as exc:
        response = f"-ERR {exc}\r\n".encode()
    finally:
        client.close()
    return response
```

- library_recommendation: `redis` (redis-py). The loaded guidance names no minimum version for this fix; confirm the resolved version against SCA/dependency-check tooling before merging. Do not pin a version from recall.

## Explanation

The original code hand-built the Redis inline-protocol command with an f-string and wrote it straight to a raw socket (`f"SET {key} {bio}\r\n"`), so any `\r\n` in `bio` (or `username`, via `key`) is read by the server as the end of one command and the start of another - the classic Redis inline-command injection (e.g. `bio = "x\r\nFLUSHALL\r\n"` executes `FLUSHALL`). The fix replaces the raw socket with `redis.Redis` (redis-py) and calls `.set(key, bio)`, which is redis-py's parameterized command API: each argument is sent to the server as a RESP bulk string with an explicit length prefix, so embedded CRLF, spaces, or command names in `bio` or `key` cannot be parsed as a new command - they arrive as literal argument bytes regardless of content. `username`/`key` and `bio` are passed as arguments, not in the command-name position, so the framing protection fully applies to both.

## Behaviour changes

- Return value: the original returned the raw bytes read back from the Redis TCP connection (whatever RESP reply the server sent). The fix cannot reuse that path once the raw socket is removed, so it synthesizes a RESP-shaped result instead: `b"+OK\r\n"` on success, or `f"-ERR {exc}\r\n".encode()` if `client.set()` raises `redis.RedisError` (e.g. connection failure). This preserves the caller's existing contract of "a bytes response" as closely as possible, but it is no longer the literal byte stream the Redis server produced - a caller that parsed more than success/failure out of that stream (e.g. specific error text) would see different content.
- Connection handling: `redis.Redis(...)` is constructed per call and explicitly `.close()`d in a `finally` block, mirroring the original's per-call `socket.create_connection(...)` / `conn.close()` lifecycle, so there is no persistent-connection behavior change.
- No validation, allowlisting, or length/character constraints were added on `username` or `bio` beyond what the fix requires. `bio` is free-form profile text with no defined format, so adding a character allowlist would be a product-behavior change (rejecting legitimate bios) rather than a security fix; the parameterized API already closes the injection without it.

## Verification

- Ran `python -m py_compile` on the fixed file (in an isolated scratch copy, not the case directory) - passed with no errors.
- Installed `redis` (resolved version 8.1.0) in an isolated environment and imported the fixed module against it - import succeeded, and `inspect.signature` confirmed `update_profile_bio(request)`'s call signature is unchanged.
- Confirmed via `inspect.signature(redis.Redis.__init__)` and `hasattr(redis.Redis, ...)` that `redis.Redis(host=..., port=..., socket_timeout=...)`, `.set()`, `.close()`, and `redis.RedisError` all exist as used - every name the fix introduces beyond the original file (`redis`, `redis.Redis`, `.set`, `.close`, `redis.RedisError`) is a standard, documented redis-py API, not assumed from recall.
