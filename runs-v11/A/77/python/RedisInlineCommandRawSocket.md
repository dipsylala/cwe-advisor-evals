## Verdict

Real issue confirmed. The inline Redis protocol command at line 13 directly interpolates user-controlled input (`bio`) into the command string without escaping, allowing attackers to inject additional Redis commands via newline characters.

## Source

The vulnerability is in the `bio` parameter from `request`, which flows directly into `conn.sendall()` as part of an unquoted inline protocol command at line 13:

```python
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

An attacker providing `bio = "value\r\nFLUSHALL"` would cause the socket to send two separate commands: the intended SET, followed by FLUSHALL.

## Fix

Switch from inline protocol to RESP (Redis Serialization Protocol), which encodes data length and content separately, preventing newlines within values from being interpreted as command boundaries:

```python
def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"user:bio:{username}"
    
    # Encode command using RESP protocol
    command = f"*3\r\n$3\r\nSET\r\n${len(key)}\r\n{key}\r\n${len(bio)}\r\n{bio}\r\n"
    conn.sendall(command.encode())
    response = conn.recv(1024)
    conn.close()
    return response
```

RESP format: `*N` = array of N elements; `$M` = bulk string of M bytes; followed by the string and `\r\n`. The `$` prefix with length ensures the value is treated as binary data regardless of its content.

## Explanation

The inline protocol (`SET key value\r\n`) treats whitespace and newlines as delimiters—injectable characters within `bio` create new commands. RESP separates metadata (command and argument count, length prefixes) from actual data, so embedded `\r\n` sequences in values are read as literal bytes within the declared length boundary, not as command terminators. This is the standard defense against Redis protocol injection and is how all production Redis clients protect against it.
