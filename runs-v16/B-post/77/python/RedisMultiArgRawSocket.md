## Verdict
exploitable

## Source
User-supplied `locale` from `request["locale"]` (line 8)

## Fix

**Vulnerable code:**
```python
conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
key = f"session:{session_id}"
# SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
response = conn.recv(1024)
conn.close()
return response
```

**Fixed code:**
```python
import redis

def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
    key = f"session:{session_id}"
    # Use redis-py's hset method with separate arguments
    result = conn.hset(key, mapping={"theme": "dark", "locale": locale})
    conn.close()
    return result
```

## Explanation

The original code builds a Redis protocol command string by concatenating user input from `request["locale"]` directly into an f-string. An attacker who controls `locale` can inject CRLF sequences to split the command—for example, `locale="dark locale evil\r\nFLUSHALL\r\n"` causes the socket to receive two separate Redis commands: the intended `HSET` followed by `FLUSHALL`. 

The fix replaces raw socket communication with redis-py's `redis.Redis` client and its `.hset()` method. redis-py uses the RESP (REdis Serialization Protocol) bulk-string framing, which encodes each argument with its length prefix, making it impossible for embedded delimiters like CRLF to be interpreted as command boundaries. The `locale` value is now passed as a separate argument to the method rather than being concatenated into a command string, and the command name itself (`HSET`) remains a literal.

## Behaviour changes

- **Return value**: The original code calls `conn.recv(1024)` and returns raw bytes from the Redis socket (a RESP integer response); the fixed code returns the integer result from `.hset()` directly (the number of fields added). The original caller must be updated to handle this different type—the original returns bytes like `b':1\r\n'`, the fixed returns the Python int `1`. If the caller requires raw bytes, call `str(result).encode()` or adjust the caller to accept the integer directly. Reason: redis-py methods return parsed values, not raw wire bytes; this is the standard contract of the library.

- **Response decoding**: The original code does not decode the socket response at all—it is raw RESP protocol bytes. The fixed code sets `decode_responses=True` so string values are automatically decoded to Python str; if this behavior is undesired, remove that parameter and handle bytes instead.

- **Connection handling**: The original creates a fresh socket for each request. The fixed code should use a connection pool in production (e.g., `redis.ConnectionPool`) rather than a single connection, to avoid connection exhaustion under load. The shown fix creates a new connection per request for parity with the original; wrap it in a pool for better performance.

## Assumptions

- **Language inference**: Confirmed Python from `.py` file extension.
- **Library**: redis-py is the standard maintained Redis client for Python. Assumed available in the project dependencies; if not present, it must be added to `requirements.txt` or equivalent. No specific version minimum is mandated by the CWE-77 guidance; use the latest stable release.
- **API existence**: `redis.Redis`, `.hset()` method, `decode_responses` parameter all exist in redis-py 3.0+. Verified by documentation and common usage patterns.
- **Return value handling**: The original function returns the socket response bytes directly. The fixed code returns an integer from `.hset()`. This is a breaking change if the caller expects bytes; adapting the caller is necessary but outside this fix's scope.
