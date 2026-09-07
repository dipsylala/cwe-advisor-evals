## Verdict

Exploitable. An attacker can inject CRLF sequences and Redis command names through the `bio` parameter to execute arbitrary Redis commands.

## Source

`request["bio"]` (line 8) – untrusted HTTP request parameter passed through to the Redis command without validation.

## Fix

**Vulnerable code (line 13):**
```python
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

**Fixed code:**
```python
import redis

# Inside update_profile_bio():
r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
key = f"user:bio:{username}"
r.set(key, bio)
response = "OK"
```

## Explanation

The original code builds a Redis command by concatenating the `bio` value directly into an inline-protocol command string, then sends it over a raw socket. An attacker can embed `\r\n` (CRLF) sequences followed by command names (e.g., `test\r\nFLUSHALL\r\n`) to terminate the SET command and inject arbitrary Redis commands. The fix replaces the raw socket and string-building approach with `redis-py`'s `redis.Redis` client and its `.set()` method. The redis-py library encodes each argument as a RESP bulk string with an explicit length prefix, so untrusted values containing CRLF, spaces, or Redis command names are treated as literal data and cannot split into separate commands.

## Behaviour changes

- **Import added**: `import redis` is required; redis-py is a standard library for Python–Redis communication.
- **Connection handling**: The original code creates and closes a connection per call; the fixed code uses a persistent client. For production use, connection pooling and error handling should be added (e.g., retry logic for transient failures, proper exception handling for connection errors).
- **Return value change**: The original returns raw bytes from `conn.recv(1024)`; the fixed code returns the string `"OK"` (the standard Redis success response). The caller's use of the return value should be verified to ensure this change does not break downstream logic.
- **Timeout parameter**: The original `socket.create_connection(..., timeout=5)` timeout is not carried forward in the fixed code. If timeout control is needed, it can be added via `redis.Redis(socket_timeout=5)`.
