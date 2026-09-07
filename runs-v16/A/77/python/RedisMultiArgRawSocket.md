## Verdict

Confirmed. The `locale` parameter from the request is interpolated directly into a Redis command string without escaping or argument separation, allowing an attacker to inject arbitrary Redis commands.

## Source

```python
def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"session:{session_id}"
    # VULNERABLE: locale is interpolated into command string
    conn.sendall(f"HSET {key} theme dark locale {locale}\r\n".encode())
    response = conn.recv(1024)
    conn.close()
    return response
```

Line 13 constructs a Redis protocol string by interpolating `locale` directly. If an attacker controls `locale` (e.g., `"en_US\r\nFLUSHALL\r\n"`), they can inject additional Redis commands.

## Fix

```python
import socket


def build_resp_command(*args):
    """Build a RESP protocol command with proper argument serialization."""
    parts = [f"*{len(args)}\r\n"]
    for arg in args:
        arg_str = str(arg)
        parts.append(f"${len(arg_str)}\r\n{arg_str}\r\n")
    return "".join(parts).encode()


def update_session_preferences(request):
    """Handle a POST to /session/preferences: persist several session
    fields in Redis in one call so preference lookups avoid a DB round trip."""
    session_id = request["session_id"]
    locale = request["locale"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"session:{session_id}"
    conn.sendall(build_resp_command("HSET", key, "theme", "dark", "locale", locale))
    response = conn.recv(1024)
    conn.close()
    return response
```

## Explanation

Command injection occurs because the code builds a Redis protocol string by string interpolation. The Redis server interprets `\r\n` as a command separator, so an attacker who controls `locale` can inject newlines and carriage returns to execute additional commands.

The fix uses RESP (Redis Serialization Protocol) binary-safe serialization: each argument is prefixed with its length (e.g., `$6\r\nlocale\r\n`), making it impossible for special characters in the argument to be interpreted as delimiters. The `build_resp_command()` helper encodes each argument value as a separate RESP bulk string, ensuring that `locale` is treated as data, never as syntax.

This approach eliminates command injection risk while remaining compatible with raw socket I/O and any Redis protocol version.
