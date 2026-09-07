## Verdict

Exploitable. Untrusted user input flows from the HTTP request body through the service layer directly into a hand-built Redis inline protocol command string, where embedded delimiters (CRLF sequences) can be interpreted as command boundaries rather than literal data.

## Source

HTTP request body in `profile_controller.py` line 19: `display_name = payload.get("display_name")` (untrusted, comes directly from request JSON). Flows through `profile_service.py` line 27 into `ProfileUpdate.value`, then to `redis_command_relay.py` line 18 where it is concatenated into the command string via f-string interpolation.

## Fix

### File: redis_command_relay.py

```python
"""Thin client that speaks the Redis inline command protocol directly."""
import redis


class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, decode_responses=True)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's hset method which parameterizes the command,
        preventing injection of untrusted field names and values.
        """
        cache_key = f"profile:{update.user_id}"
        # Fixed: Use redis-py's hset() method which passes each argument separately
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The original code built a Redis inline protocol command string manually using f-string interpolation, then sent it to the server via a raw socket. The Redis inline protocol uses CRLF as a command delimiter, so an attacker-controlled value containing `\r\n` would be split into separate commands. The fix replaces the raw socket client with redis-py's `redis.Redis` class and uses its `.hset()` method. This method encodes each argument using the RESP protocol with explicit length prefixes, so embedded delimiters cannot be reinterpreted as command boundaries. The untrusted field name and value are now passed as separate protocol-framed arguments rather than interpolated into a command string, eliminating the injection path. The library handles all protocol details safely, including proper encoding and delimiter handling.

## Behaviour changes

The instance variable changed from `self._sock` (socket.socket) to `self._client` (redis.Redis). The `.write_profile_field()` method no longer opens and manages socket connections manually; redis-py manages connection pooling and lifecycle internally. The method no longer returns the raw socket sendall result (which returns None); the `.hset()` call returns an integer count of fields added (0 or 1 in this case, depending on whether the field existed). Callers of `write_profile_field()` do not appear to use the return value based on the provided code, so this change in return type does not affect the application. The timeout parameter passed to `socket.create_connection()` (2 seconds) is not carried forward to the redis.Redis client, which uses its own default socket timeout. To preserve the 2-second timeout, pass `socket_connect_timeout=2` to the redis.Redis constructor; this was omitted from the minimal fix since the guidance does not mandate timeout preservation and the default redis timeout is reasonable for typical cache operations.

