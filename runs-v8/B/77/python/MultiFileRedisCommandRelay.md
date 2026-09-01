## Verdict

Exploitable. User-controlled input (`display_name` from the HTTP request) reaches the Redis protocol command builder without validation or parameterization, allowing command injection via embedded newlines or whitespace.

## Source

`profile_controller.py` line 19: `display_name = payload.get("display_name")` receives untrusted HTTP request data.

Data flows through `ProfileService.update_display_name()` (profile_service.py line 26), into a `ProfileUpdate` object (profile_service.py line 27), and finally to `RedisCommandRelay.write_profile_field()` (redis_command_relay.py line 18), where it is interpolated directly into a Redis command string.

## Fix

**Vulnerable code (redis_command_relay.py):**
```python
def write_profile_field(self, update):
    """Write a single profile field into the user's cache hash."""
    cache_key = f"profile:{update.user_id}"
    command = f"HSET {cache_key} {update.field} {update.value}\r\n"
    # Sink: untrusted values embedded in command string
    self._sock.sendall(command.encode("utf-8"))
```

**Fixed code (redis_command_relay.py):**
```python
import redis

class RedisCommandRelay:
    """Hand-rolled Redis client using redis-py for safe command execution."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, decode_responses=True, socket_connect_timeout=2)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.
        
        Uses redis-py's hset() method, which frames each argument as a separate 
        RESP bulk string, preventing embedded delimiters from being interpreted 
        as command boundaries.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The original code hand-built a Redis inline command string using f-string interpolation and sent it over a raw socket. The Redis inline protocol uses `\r\n` as a command terminator, so an attacker who controls `display_name` can inject newlines to execute arbitrary Redis commands (e.g., `display_name = "value\r\nFLUSHALL\r\n"`).

The fix replaces the raw socket and string-building pattern with `redis-py`, a maintained client library that encodes each argument as a RESP bulk string with an explicit length prefix. This framing ensures that special characters—including newlines, spaces, and command names—in field names and values are treated as literal data, not protocol delimiters. The `.hset()` method receives `cache_key`, `field`, and `value` as separate arguments, each safely framed by the library.

The timeout parameter (`socket_connect_timeout=2`) preserves the original 2-second socket timeout behavior from `socket.create_connection()`.

## Behaviour changes

- **Connection handling**: Replaced raw socket creation (`socket.create_connection()`) with `redis.Redis` client, which manages a connection pool internally. This is a transparent change—the application still connects to the same Redis server on the same host and port, but benefits from connection pooling for concurrent requests.
- **Timeout semantics**: `socket_connect_timeout=2` on the Redis client sets the connection-establishment timeout (equivalent to `timeout=2` on `socket.create_connection()`), preserving the original behavior.
- **Return value**: `redis.hset()` returns an integer (number of fields added), whereas the original `socket.sendall()` returned `None`. The calling code in `profile_service.py` does not use a return value, so this has no impact.
- **Exception handling**: `redis.hset()` raises `redis.RedisError` on connection or command failure, whereas raw socket operations raise `OSError` or `socket.timeout`. If the calling code does not already handle these, a blanket exception handler may need to catch the broader `Exception` or the specific `redis.RedisError`.
