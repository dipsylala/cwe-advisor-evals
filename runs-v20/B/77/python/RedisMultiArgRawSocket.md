## Verdict

exploitable (confidence: high)

## Source

`request["session_id"]` and `request["locale"]`, both taken directly from an incoming HTTP request in `update_session_preferences`, with no validation or encoding applied before use.

## Fix

Sink: `conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())` at line 13, where `key` embeds `session_id` and the command string embeds `locale`. The call opens a raw TCP socket to the Redis port and writes a hand-built Redis "inline protocol" command line terminated by `\r\n`. Both `session_id` and `locale` reach this line unsanitized: either one containing `\r\n` terminates the current command and starts a new one that Redis will execute (e.g. `\r\nFLUSHALL\r\n`), and either one containing a space adds extra tokens/arguments to the `HSET` call. This is CWE-77 against the Redis wire protocol, not the OS shell.

Sink contract before the fix:
- **Returns**: `conn.recv(1024)`, the raw RESP-encoded reply bytes read directly off the socket (e.g. `b":2\r\n"` for an integer reply), returned as-is to the caller as `response`.
- **Discards**: nothing beyond the reply bytes not consumed if longer than 1024 bytes (unhandled by the original code either).
- **Arguments left implicit**: the socket connect timeout (`timeout=5`) and no read timeout; no error handling around `recv`/`sendall`.
- **Failure behaviour**: any socket error (connection refused, timeout) propagates as an unhandled exception out of `update_session_preferences`.

### File: RedisMultiArgRawSocket.py

```python
import redis


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = redis.Redis(host="127.0.0.1", port=6379, socket_timeout=5)
    key = f"session:{session_id}"
    response = conn.hset(key, mapping={"theme": "dark", "locale": locale})
    conn.close()
    return response
```

**Library recommendation**: `redis` (redis-py) from PyPI. The loaded guidance does not carry a minimum safe version for this library; confirm the resolved version against SCA/dependency-check tooling before merging.

## Explanation

The fix replaces the hand-built inline-protocol command string with redis-py's `Redis.hset(name, mapping=...)`, so the connection is no longer raw application code writing bytes to a socket. redis-py frames `key` and each mapping value as its own RESP bulk string with an explicit length prefix before sending it, so an embedded `\r\n`, space, or command name in `session_id` or `locale` is transmitted as literal data inside that one argument and cannot be read by the server as a command terminator or as additional arguments/commands. The command verb (`HSET`) and field names (`theme`, `locale`) stay as literals chosen by the code, and only the values move as untrusted data - never as part of a concatenated string - closing the injection.

## Behaviour changes

- **Return type of `response`**: was raw RESP-encoded bytes read via `socket.recv()` (e.g. `b":2\r\n"`); now `conn.hset()`'s own return value, an `int` giving the number of fields that were newly added to the hash (fields that already existed and were merely updated are not counted). Any caller that parsed or forwarded the raw bytes will need updating to consume the int instead. This is a necessary consequence of moving off the raw socket - preserving the RESP encoding would mean keeping the raw protocol, which is the pattern being replaced.
- **Connection object type**: `conn` is now a `redis.Redis` client instance rather than a `socket.socket`; `.close()` is still called at the end, matching the original's per-call open/close lifecycle.
- **Timeout semantics**: `socket_timeout=5` on `redis.Redis` maps to the same request timeout the original applied via `socket.create_connection(..., timeout=5)`; no change in effective timeout value.
- Everything else (host, port, per-call connection lifecycle, the two fields written, the key naming scheme) is unchanged.

## Verification

Ran `python -m py_compile` (uv-managed CPython 3.13.12 interpreter) against the fixed file in a scratch copy outside the repository: compiled cleanly, no syntax errors. `redis.Redis` and `Redis.hset(name, mapping=...)` are the documented public constructor and method of the `redis` package (redis-py) named in the loaded language guidance; no other new names were introduced. The `redis` package itself was not importable in this environment (not installed), so the call was checked by hand against the guidance and the well-known redis-py client API rather than by executing it.
