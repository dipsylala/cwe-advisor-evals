## Verdict

Exploitable. The `display_name` value from the HTTP request body flows untrusted through the service layer and is concatenated directly into a raw Redis command string at line 18 of `redis_command_relay.py`, then sent via raw socket at line 20. An attacker can inject Redis protocol delimiters (e.g., `\r\nFLUSHALL\r\n`) to execute arbitrary commands on the Redis server.

## Source

HTTP POST request body parameter `display_name` in `profile_controller.py` line 19, passed untrusted through `profile_service.py` line 27 to the `ProfileUpdate` DTO's `value` field, then to `redis_command_relay.py` line 18.

## Fix

**Vulnerable code** (lines 1-20 of `redis_command_relay.py`):

```python
"""Thin client that speaks the Redis inline command protocol directly."""
import socket


class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._sock = socket.create_connection((host, port), timeout=2)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Builds the Redis inline command by hand instead of using redis-py,
        so the field value is concatenated straight into the command text.
        """
        cache_key = f"profile:{update.user_id}"
        command = f"HSET {cache_key} {update.field} {update.value}\r\n"  # <-- CWE-77: Untrusted field and value concatenated into command
        self._sock.sendall(command.encode("utf-8"))  # <-- Sink: sent via raw socket without framing
```

**Fixed code**:

```python
"""Redis client using the redis-py parameterized API."""
import redis


class RedisCommandRelay:
    """Redis client using redis-py for safe command construction."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            socket_connect_timeout=2
        )

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's .hset() method, which passes field and value
        as separate RESP bulk string arguments, preventing delimiter injection.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The fix replaces the raw socket connection and hand-built command string with the `redis.Redis` client from redis-py (pip package `redis`). Instead of concatenating field and value into a command string (`HSET key field value\r\n`), the `.hset()` method encodes each argument as a RESP (Redis Serialization Protocol) bulk string with an explicit length prefix. An attacker-supplied value like `admin\r\nFLUSHALL\r\n` is now stored as literal data in the hash field rather than parsed by Redis as a separate command, because the protocol framing prevents the embedded delimiter from reaching the Redis parser. The `decode_responses=True` parameter returns strings instead of bytes, matching the original code's intent. The `socket_connect_timeout` parameter preserves the original 2-second timeout behaviour.

## Behaviour changes

1. **Connection pooling**: redis-py manages connection pooling and reuse internally, whereas the original code opens a single persistent socket. This is a transparent improvement with no semantic change.
2. **Error handling**: `.hset()` can raise `redis.exceptions.RedisError` or connection exceptions on failure, whereas the original `sendall()` silently succeeded or raised `socket.error`. Calling code must handle these exceptions rather than assuming success; this is appropriate since network errors should not be silently ignored.
3. **Return value**: `.hset()` returns an integer (number of fields added: 1 if new, 0 if updated), whereas the original `sendall()` returned `None`. Calling code currently does not check the return value, so this change is safe; if error detection is needed, the return value or exception handling can be used.
4. **Import statement**: Code must import `redis` from the redis-py package instead of socket; this requires adding `redis` to the project dependencies.
5. **Timeout semantic**: The original timeout was for socket connection establishment; redis-py's `socket_connect_timeout` is equivalent and preserves the original intent, whereas the socket timeout would also apply to data transmission and might not align with actual needs.
