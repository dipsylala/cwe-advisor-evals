## Verdict

The finding is confirmed and exploitable. Untrusted HTTP input (`display_name` from the request) flows through the service layer and reaches the Redis sink via raw string concatenation, allowing command injection.

## Source

**profile_controller.py, line 19**: `display_name = payload.get("display_name")`

HTTP request body parameter passed without validation to the service layer.

**Data flow**: HTTP request → profile_controller.py:24 → profile_service.py:27 (wrapped in DTO) → profile_service.py:32 → redis_command_relay.py:18 (string concatenation)

## Fix

Replace the hand-built socket command string with redis-py's typed client methods. Each argument is framed as a RESP bulk string with explicit length, preventing embedded delimiters from being interpreted as command boundaries.

**redis_command_relay.py**:

```python
"""Thin client that speaks the Redis inline command protocol directly."""
import redis


class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, decode_responses=True)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's typed methods to safely pass each argument,
        preventing command injection through untrusted field values.
        """
        cache_key = f"profile:{update.user_id}"
        # FIXED: Use redis.hset() with field and value as separate arguments.
        # redis-py encodes each argument as a RESP bulk string with explicit length,
        # so embedded delimiters cannot be interpreted as command boundaries.
        self._client.hset(cache_key, mapping={update.field: update.value})
```

## Explanation

The original code constructs a Redis inline protocol command via f-string concatenation, treating the untrusted `update.value` as a literal part of the command text. An attacker can inject `\r\nFLUSHALL\r\n` or similar sequences to split the command and execute arbitrary Redis commands.

The fix replaces the raw socket and string building with redis-py's `Redis` client and `.hset()` method. This leverages redis-py's RESP protocol encoder, which wraps each argument (including the field name and value) as a bulk string with an explicit byte-count prefix. When redis-py sends the framed arguments to the server, embedded `\r\n` and command keywords are treated as literal data bytes within the value, not as protocol delimiters or commands.

**Defence-in-depth**: Consider adding a dedicated Redis ACL user for the application connection with limited permissions (e.g., read/write restricted to the `profile:*` keyspace, explicitly excluding `FLUSHALL`, `FLUSHDB`, `SWAPDB`). This limits damage if the application is compromised through a different vector.

## Behaviour changes

- **Arguments**: Now passed through redis-py's RESP encoder instead of Python f-string formatting. No visible change in application behavior for legitimate input.
- **Error handling**: redis-py raises `redis.exceptions.RedisError` or subclasses (e.g., `ConnectionError`, `ResponseError`) instead of socket errors. Applications should update error handling if socket-specific exceptions are caught.
- **Timeout**: The `socket.create_connection(timeout=2)` is replaced with redis-py's default timeouts. If strict 2-second socket timeout is critical, set `socket_timeout=2` in the `Redis()` constructor.
- **Connection pooling**: redis-py uses connection pooling by default, whereas the original code maintained a single persistent socket. This is transparent to the application but uses slightly more memory for the pool.
- **Encoding**: The original code called `.encode("utf-8")` explicitly; redis-py handles encoding internally. The `decode_responses=True` parameter ensures string values are returned as Python strings rather than bytes.

The injection vulnerability is eliminated: untrusted values in `update.field` and `update.value` can no longer escape the argument boundary to create a second command.
