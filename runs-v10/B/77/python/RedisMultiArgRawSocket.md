## Verdict

**Confirmed.** CWE-77 command injection. The `locale` parameter from `request` is interpolated into a hand-built Redis inline-protocol command string and sent over a raw socket. An attacker-controlled value containing `\r\n` can inject additional Redis commands that execute on the server.

## Source

**File:** `RedisMultiArgRawSocket.py`, line 13  
**Vulnerable pattern:**
```python
conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
```

**Data flow:**
- Untrusted source: `request["locale"]` (line 8)
- Sink: `conn.sendall()` with string-interpolated command (line 13)
- The value flows directly into the command string with no neutralization of Redis protocol delimiters

**Exploitable if:** `locale` contains newlines or Redis command syntax (e.g., `"evil\r\nFLUSHALL\r\n"`) - the injected commands execute as separate Redis operations.

## Fix

**Replace the raw socket code with redis-py's parameterized API:**

```python
import redis

def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True, socket_connect_timeout=5)
    key = f"session:{session_id}"
    # Use hset() with separate arguments; redis-py encodes each value as a RESP bulk string
    response = conn.hset(key, mapping={"theme": "dark", "locale": locale})
    conn.close()
    return response
```

**Key changes:**
- Replace raw `socket` connection with `redis.Redis()` client
- Use `.hset()` method with `mapping` parameter instead of building a command string
- Each value (`"dark"`, `locale`) is passed as a separate argument to `.hset()`
- redis-py encodes each argument as a RESP bulk string with explicit length framing

## Explanation

The vulnerability stems from hand-building a Redis inline-protocol command by string concatenation. The Redis inline protocol uses `\r\n` as a command terminator; when untrusted input containing `\r\n` is embedded directly, it splits the command string into multiple commands that all execute.

redis-py's `.hset()` method eliminates this by using the RESP (Redis Serialization Protocol) bulk-string encoding for each argument. Each value gets framed with its byte length prefix (e.g., `$4\r\ndata\r\n`), so embedded delimiters become literal data and cannot split into separate commands. The command name (`HSET`) remains a literal; only the key and field/value pairs are data.

The fix also simplifies the code by replacing socket plumbing with a high-level client library, which handles connection pooling, timeouts, and error handling.

## Behaviour changes

**Response value type:** The original code returns the raw bytes from `conn.recv(1024)` (a `bytes` object). The fixed code returns the integer value from `.hset()` (the number of fields added), a different type and value. If the caller expects the raw protocol response, it must be adapted to parse the redis-py return value or switch to `.execute_command()` for lower-level control.

**Connection handling:** The original code opens a new socket per request and closes it immediately. The fixed code's default `redis.Redis()` client instance manages a single persistent connection. For a high-traffic service, this improves performance; for short-lived processes or tests, the connection is closed when the client is garbage-collected (or explicitly with `.close()`).

**Error handling:** The original code silently passes through socket errors; redis-py raises `redis.ConnectionError`, `redis.ResponseError`, and other redis-specific exceptions. The caller must handle these if the original code was intentionally suppressing them.
