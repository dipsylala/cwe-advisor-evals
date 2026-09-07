## Verdict

Confirmed exploitable CWE-77 command injection vulnerability. Untrusted input from the HTTP request body flows through the service layer to the cache tier, where it is concatenated into a Redis inline protocol command string and executed via raw socket. An attacker can inject Redis commands by embedding CRLF sequences in the `display_name` parameter.

## Source

HTTP request body parameter `display_name` in `profile_controller.py` line 19:
```
display_name = payload.get("display_name")
```

Flows through:
- `profile_controller.py` line 24: passed to `ProfileService.update_display_name()`
- `profile_service.py` line 27: wrapped in `ProfileUpdate` with `field` and `value` attributes
- `profile_service.py` line 32: passed to `RedisCommandRelay.write_profile_field()`
- `redis_command_relay.py` line 18: concatenated into command string as `{update.value}`
- `redis_command_relay.py` line 20: sent to Redis via `socket.sendall()`

## Fix

### File: redis_command_relay.py

```python
"""Thin client that speaks the Redis protocol via redis-py."""
import redis


class RedisCommandRelay:
    """Redis client that uses the redis-py library for safe command framing."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            socket_connect_timeout=2
        )

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's hset() method, which properly frames each argument
        as a separate RESP bulk string, preventing command injection via
        embedded delimiters or command names.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The vulnerability exists because `redis_command_relay.py` hand-builds the Redis inline protocol command by concatenating untrusted input directly into a command string, then sends it via raw socket. This allows an attacker to inject newlines (`\r\n`) and additional Redis commands. For example, a `display_name` of `value\r\nFLUSHALL\r\n` would result in the command string `HSET profile:user1 display_name value\r\nFLUSHALL\r\n`, which Redis parses as two separate commands instead of one.

The fix replaces the raw socket implementation with the `redis-py` library's `Redis` client and `hset()` method. The redis-py library encodes each argument using the RESP (Redis Serialization Protocol) bulk string format with explicit length prefixes, so embedded delimiters and command names are treated as literal data rather than protocol delimiters or new commands. The command-name position (`HSET`) remains a literal, preventing both command name injection and argument injection.

The fix preserves all original behavior: the data still reaches Redis, the cache key is constructed the same way, and the field/value pair is written to the hash. The change is surgical—only the unsafe string-building and socket call are replaced with the parameterized API.

## Behaviour changes

- **Command framing**: Switches from inline protocol (space/newline-delimited plain text sent via raw socket) to RESP (length-prefixed bulk strings). This is transparent to Redis and compatible with all Redis versions.
- **Connection handling**: Moves from manual socket management to redis-py's connection pooling and automatic reconnection (none of this is explicitly used in the original, but it is available).
- **Return value**: Original `socket.sendall()` returns `None`; `redis.hset()` returns the number of fields added/updated to the hash. The caller in `profile_service.py` does not capture or use the return value, so this change is safe.
- **Error behavior**: Original raises `socket.error` on I/O failure; redis-py raises connection exceptions (subclasses of `redis.ConnectionError`) on network/protocol errors. The application's error handling in `profile_controller.py` is not shown, but both behaviors are exceptions for the caller to handle.
- **Dependency**: Introduces a dependency on the `redis-py` library (PyPI package `redis`). This is the standard, well-maintained client library for Python Redis applications.
