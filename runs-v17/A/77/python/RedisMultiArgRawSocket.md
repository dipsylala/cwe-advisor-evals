## Verdict
CWE-77 vulnerability confirmed. The code constructs a Redis command using string interpolation with unsanitized user input, allowing command injection via embedded `\r\n` sequences.

## Source
Line 13 in RedisMultiArgRawSocket.py sends a Redis command constructed by interpolating the `locale` request parameter directly into the command string:
```
conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
```

An attacker controlling `locale` can inject `\r\n` to terminate the current command and inject new ones, bypassing intended command boundaries.

## Fix
### File: RedisMultiArgRawSocket.py
```python
import socket


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"session:{session_id}"
    
    # Build RESP (Redis Serialization Protocol) array command to safely send arguments
    locale_bytes = locale.encode()
    key_bytes = key.encode()
    
    # HSET key field1 value1 field2 value2
    # Command parts: HSET, key, "theme", "dark", "locale", locale_value
    parts = [b"HSET", key_bytes, b"theme", b"dark", b"locale", locale_bytes]
    
    # Build RESP array format with length prefixes
    # *<count>\r\n for array header, then $<len>\r\n<data>\r\n for each element
    resp_command = f"*{len(parts)}\r\n".encode()
    for part in parts:
        resp_command += f"${len(part)}\r\n".encode() + part + b"\r\n"
    
    conn.sendall(resp_command)
    response = conn.recv(1024)
    conn.close()
    return response
```

## Explanation
The fix switches from simple string interpolation to the Redis Serialization Protocol (RESP), which is the wire protocol Redis expects. RESP sends commands as arrays where each element is a bulk string prefixed with its length.

Key protection: Length prefixes (`$<len>`) tell Redis exactly how many bytes comprise each argument. An attacker-controlled `locale` value is transmitted as a single bulk string whose length is known and fixed—`\r\n` inside the value is treated as literal data, not a protocol delimiter. The command structure (array count, field names) is separated from the argument data by the length encoding, making injection impossible.

This is the correct way to send commands to Redis when using raw sockets: structure (array markers, field names) and data (user input) are distinguished at the protocol level, not by output encoding.
