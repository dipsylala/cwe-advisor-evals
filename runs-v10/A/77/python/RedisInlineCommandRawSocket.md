## Verdict

Confirmed CWE-77: Command Injection via Redis inline protocol. The `bio` parameter is directly concatenated into a Redis command string without escaping, allowing an attacker to inject `\r\n` delimiters and arbitrary Redis commands.

## Source

```python
username = request["username"]
bio = request["bio"]
conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
key = f"user:bio:{username}"
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

An attacker controlling the `bio` parameter can supply a value like `"evil\r\nFLUSHALL\r\n"` to execute arbitrary Redis commands after the SET, bypassing the intended operation.

## Fix

Use the Redis Serialization Protocol (RESP) to send commands safely. RESP uses length-prefixed arguments, preventing `\r\n` in the data from being interpreted as command separators:

```python
import socket

def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"user:bio:{username}"
    
    # Build RESP command: *3\r\n$3\r\nSET\r\n$<key_len>\r\n<key>\r\n$<bio_len>\r\n<bio>\r\n
    key_bytes = key.encode()
    bio_bytes = bio.encode()
    command = (
        b"*3\r\n"
        b"$3\r\nSET\r\n"
        f"${len(key_bytes)}\r\n".encode() + key_bytes + b"\r\n"
        f"${len(bio_bytes)}\r\n".encode() + bio_bytes + b"\r\n"
    )
    
    conn.sendall(command)
    response = conn.recv(1024)
    conn.close()
    return response
```

Alternatively, use a Redis client library like `redis-py` that handles RESP encoding automatically:

```python
import redis

def update_profile_bio(request):
    username = request["username"]
    bio = request["bio"]
    r = redis.Redis(host="127.0.0.1", port=6379, decode_responses=True)
    key = f"user:bio:{username}"
    r.set(key, bio)
    return b"+OK\r\n"
```

## Explanation

The Redis inline protocol (used by `conn.sendall(f"SET {key} {bio}\r\n".encode())`) treats `\r\n` as a command delimiter. Because `bio` is untrusted user input concatenated directly into the command string, an attacker can embed `\r\n` to terminate the current command and inject additional commands.

The RESP protocol solution wraps each argument in a length prefix (`$<length>\r\n`), so embedded `\r\n` characters within the data are treated as literal bytes, not delimiters. The array header (`*3`) indicates three arguments follow: the command name and two operands.

A Redis client library is preferable because it handles RESP encoding transparently and provides additional safety features like connection pooling and exception handling.
