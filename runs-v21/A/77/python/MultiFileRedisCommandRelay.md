## Verdict

**CONFIRMED**. This is a command injection vulnerability in the Redis inline protocol implementation. An attacker who controls the `display_name` parameter can inject arbitrary Redis commands by including CRLF sequences, bypassing the single-command assumption and potentially executing unintended operations like FLUSHALL or data exfiltration.

## Source

The vulnerability is in `redis_command_relay.py`, line 20. The `write_profile_field()` method builds a Redis inline command by directly concatenating user-controlled data:

```python
command = f"HSET {cache_key} {update.field} {update.value}\r\n"
self._sock.sendall(command.encode("utf-8"))
```

The `update.value` comes from the request body (via `profile_controller.py` → `profile_service.py`) without sanitization. An attacker can inject newlines and additional Redis commands. For example, a `display_name` of `"Alice\r\nFLUSHALL\r\n"` would send two separate commands to Redis.

## Fix

### File: redis_command_relay.py

```python
"""Redis client that safely handles cache writes."""
import redis


class RedisCommandRelay:
    """Redis client using the protocol library for safe command handling."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, socket_connect_timeout=2, decode_responses=False)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses the redis-py library to safely encode field and value,
        preventing command injection attacks. The redis library uses
        the Redis Serialization Protocol (RESP) internally, which is
        binary-safe and cannot be broken by control characters.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The fix replaces the vulnerable inline protocol implementation with the `redis-py` library, which:

1. **Uses RESP (Redis Serialization Protocol)**: RESP is binary-safe and uses length-prefixed strings. It cannot be broken by CRLF characters or other metacharacters embedded in data.

2. **Prevents argument confusion**: RESP explicitly encodes the number and length of each argument, so user-supplied data cannot be interpreted as command boundaries or separate commands.

3. **Maintains the same interface**: The method signature and behavior remain unchanged. The callers in `profile_service.py` and `profile_controller.py` require no modification.

4. **Matches the timeout intent**: The `socket_connect_timeout=2` parameter preserves the original socket timeout behavior from `socket.create_connection(..., timeout=2)`.

The root cause of CWE-77 here is mixing data with command structure in a text-based protocol. Using a proper library with binary-safe serialization is the standard defense.
