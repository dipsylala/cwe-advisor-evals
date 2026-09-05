## Verdict

Real command injection vulnerability via Redis inline protocol.

## Source

Line 13 constructs a Redis command by string interpolation with unsanitized user input:

```python
bio = request["bio"]
conn.sendall(f"SET {key} {bio}\r\n".encode())
```

The `bio` parameter originates from untrusted user input (`request["bio"]`) and is directly embedded in the command string. Redis's inline protocol (space-delimited) interprets newlines as command separators, allowing injection of arbitrary commands.

## Fix

Replace the inline protocol with Redis's RESP (REdis Serialization Protocol), which uses length-prefixed encoding that safely isolates arguments from injection:

```python
def update_profile_bio(request):
    """Handle a POST to /profile/bio: cache the user's bio text in Redis
    so the profile page can render it without hitting the primary DB."""
    username = request["username"]
    bio = request["bio"]

    conn = socket.create_connection(("127.0.0.1", 6379), timeout=5)
    key = f"user:bio:{username}"
    
    # Use RESP protocol: *3 (3 elements), $3 "SET", $len key, $len bio
    command = f"*3\r\n$3\r\nSET\r\n${len(key)}\r\n{key}\r\n${len(bio)}\r\n{bio}\r\n"
    conn.sendall(command.encode())
    
    response = conn.recv(1024)
    conn.close()
    return response
```

Alternatively, use a Redis library like `redis-py` which handles protocol encoding internally:

```python
import redis

def update_profile_bio(request):
    username = request["username"]
    bio = request["bio"]
    
    client = redis.Redis(host="127.0.0.1", port=6379)
    key = f"user:bio:{username}"
    client.set(key, bio)
    return b"+OK\r\n"
```

## Explanation

Redis's inline protocol (used when sending plain text commands) is space-delimited and terminates on `\r\n`. Newlines within the `bio` parameter act as command separators, permitting attackers to inject extra commands. For example, if `bio` contains `hello\r\nDEL user:bio:admin`, the server executes two separate commands: `SET` and `DEL`.

The RESP protocol fixes this by length-prefixing arguments (`$len\r\nvalue\r\n`). Since the server reads exactly `len` bytes for each argument, embedded newlines are treated as literal characters and never trigger command parsing.

Using a client library like `redis-py` avoids manual protocol construction and is the preferred solution for production code.
