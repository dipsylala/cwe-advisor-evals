## Verdict

Exploitable. Untrusted `display_name` from the HTTP request body flows through `ProfileService.update_display_name()` and `RedisCommandRelay.write_profile_field()` into a hand-built Redis inline-protocol command string, then to `socket.sendall()` without parameterization. A value containing `\r\n` splits the command: e.g., `"attacker\r\nFLUSHALL\r\n"` produces both the intended HSET and a destructive FLUSHALL command.

## Source

**Taint source:** HTTP POST body parameter `display_name` in `profile_controller.py:24` (`request.get_json()`)

**Call chain:**
1. `profile_controller.py:24` - `display_name = payload.get("display_name")` (untrusted user input)
2. `profile_controller.py:24` - passed to `ProfileService.update_display_name(user_id=..., display_name=display_name)`
3. `profile_service.py:27` - bundled into `ProfileUpdate(value=display_name)`
4. `profile_service.py:32` - passed to `RedisCommandRelay.write_profile_field(update)`
5. `redis_command_relay.py:18` - interpolated into command string: `f"HSET {cache_key} {update.field} {update.value}\r\n"`
6. `redis_command_relay.py:20` - sent via raw socket: `self._sock.sendall(command.encode("utf-8"))`

**Taint sink:** `redis_command_relay.py:20` - `socket.sendall()` with hand-built Redis inline-protocol command

## Fix

**Vulnerable code** (`redis_command_relay.py`):
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
        command = f"HSET {cache_key} {update.field} {update.value}\r\n"
        # VULNERABLE: Untrusted field and value are concatenated into the command string
        self._sock.sendall(command.encode("utf-8"))
```

**Fixed code** (`redis_command_relay.py`):
```python
"""Redis client using the redis-py library for safe command construction."""
import redis


class RedisCommandRelay:
    """Redis client using redis-py to safely frame each argument."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            socket_connect_timeout=2
        )

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's hset() method which parameterizes each argument,
        preventing command injection via embedded delimiters.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The fix replaces the hand-built Redis inline-protocol command with `redis-py`'s `hset()` method. The redis-py library encodes each argument as a RESP (REdis Serialization Protocol) bulk string with an explicit length prefix; this framing means embedded newlines, spaces, and command names in `update.field` and `update.value` are treated as literal data, not command delimiters. The command name (`HSET`) remains a literal string under programmer control, and each untrusted parameter is passed as its own argument where it cannot alter the command structure. This closes the injection point while preserving the original functionality: setting a hash field in the Redis cache.

## Behaviour changes

None. The `redis.Redis` client's `hset(key, mapping)` method signature performs the same operation as the raw `HSET key field value` command: it sets a single field in a hash. The socket timeout is preserved via `socket_connect_timeout=2`. The `decode_responses=True` flag returns string values instead of bytes, which matches the original intent (the field value originates as a Python string and is used as a string). Connection pooling and error handling are handled transparently by redis-py, which is superior to the hand-rolled socket management but does not alter the observable behaviour of a successful write.

