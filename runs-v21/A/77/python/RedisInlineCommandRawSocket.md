## Verdict
CONFIRMED: CWE-77 command injection via unescaped user input in Redis inline protocol.

## Source
The vulnerable code constructs a Redis inline protocol command by string interpolation, concatenating user-controlled `bio` directly into the command:
```python
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

An attacker controlling the `bio` parameter can inject CRLF sequences to execute arbitrary Redis commands. For example, `bio="hello\r\nGET password"` would execute both SET and GET commands.

## Fix
Use the Redis Serialized Protocol (RESP) which encodes commands as length-prefixed bulk strings, making special characters data rather than command syntax:

### File: RedisInlineCommandRawSocket.py
```python
import socket


def encode_resp_bulk_string(data):
    """Encode a string as a RESP bulk string."""
    if isinstance(data, str):
        data = data.encode()
    return f"${len(data)}\r\n".encode() + data + b"\r\n"


def send_command(conn, *args):
    """Send a Redis command using RESP protocol to prevent command injection."""
    # Build RESP array with command and arguments
    command = f"*{len(args)}\r\n".encode()
    for arg in args:
        command += encode_resp_bulk_string(arg)
    conn.sendall(command)


def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"user:bio:{username}"
    # Use RESP protocol to safely send the SET command
    send_command(conn, "SET", key, bio)
    response = conn.recv(1024)
    conn.close()
    return response
```

## Explanation
The Redis Serialized Protocol (RESP) uses structured message encoding:
- Arrays prefixed with `*<count>\r\n` indicating argument count
- Bulk strings prefixed with `$<length>\r\n` followed by the string data and `\r\n`

This structure ensures that the length-prefixed format enforces parsing boundaries. The `bio` value is now transmitted as data with its exact length, so injected CRLF sequences are treated as string content, not command delimiters. The command `send_command(conn, "SET", key, bio)` encodes all three arguments as bulk strings within an array, making command injection impossible regardless of the input content.
