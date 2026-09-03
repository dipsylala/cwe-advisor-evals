## Verdict

CWE-77 Command Injection confirmed. The `update.value` (originating from user-supplied `display_name` in the HTTP request) is concatenated directly into a Redis inline command string without escaping. An attacker can inject newline and carriage return characters to add arbitrary Redis commands.

## Source

The data flow originates in `profile_controller.py` line 19, where `display_name` is extracted from the JSON request body without validation. This value flows through `profile_service.py` line 27 (passed to `ProfileUpdate`), then to `redis_command_relay.py` line 18 where it is concatenated into the command string, and finally executed at line 20 via `self._sock.sendall()`.

## Fix

Replace the hand-rolled Redis inline command protocol with redis-py's `HSET` method, which handles proper command construction and argument escaping:

```python
import redis

class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, decode_responses=True)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.
        
        Uses redis-py to safely construct the HSET command with proper
        argument separation and escaping.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The vulnerability exists because the Redis inline protocol uses whitespace and `\r\n` as delimiters. By concatenating user input directly into the command string, an attacker can embed these characters (e.g., `display_name = "evil\r\nFLUSHALL\r\n"`) to inject and execute arbitrary Redis commands.

The redis-py library uses the Redis Serialization Protocol (RESP), which transmits commands as an array of bulk strings with explicit length prefixes. This protocol boundary prevents the attacker's string from ever being interpreted as command delimiters—the entire value is treated as a single bulk string argument, regardless of its content.

This fix also eliminates socket management code and improves resilience through redis-py's connection pooling and error handling.
