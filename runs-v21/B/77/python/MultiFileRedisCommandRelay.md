## Verdict

Confirmed: CWE-77 command injection via untrusted input concatenated into a Redis inline protocol command string.

## Source

**Call chain:** HTTP request body → Flask handler → ProfileService → RedisCommandRelay.write_profile_field() → socket.sendall()

**Entry point:** `profile_controller.py` line 19 receives untrusted `display_name` from JSON request.

**Sink:** `redis_command_relay.py` line 20 sends hand-built command via `socket.sendall()`.

**Data flow:** The `display_name` value is passed through `ProfileService.update_display_name()` (profile_service.py line 24), wrapped in a `ProfileUpdate` DTO (line 27), and concatenated directly into a Redis inline protocol command string (redis_command_relay.py line 18): `f"HSET {cache_key} {update.field} {update.value}\r\n"`.

**Exploitability:** An attacker can inject Redis commands by including `\r\n` in the `display_name` field. Example payload: `"admin\r\nFLUSHALL\r\n"` would be concatenated into multiple commands, allowing arbitrary Redis operations.

## Fix

### File: redis_command_relay.py

```python
"""Thin client that speaks Redis via the redis-py library."""
import redis


class RedisCommandRelay:
    """Redis client using redis-py for safe command construction."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, socket_connect_timeout=2, decode_responses=True)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's .hset() method to safely pass each argument as a
        separately framed value, preventing command injection.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The vulnerability stems from hand-building Redis inline protocol commands by concatenating untrusted values. The Redis inline protocol uses `\r\n` as a command delimiter, so injecting `\r\n` allows an attacker to execute arbitrary commands.

The fix replaces the raw `socket`-based approach with the `redis-py` library's `Redis` client. The `.hset()` method encodes each argument as a RESP (Redis Serialization Protocol) bulk string with an explicit length prefix, ensuring that delimiters and special characters in values are treated as literal data rather than protocol syntax. This is the standard, recommended pattern per CWE-77 Python guidance.

**Key changes:**
1. Import `redis` instead of `socket`
2. Replace socket connection with `redis.Redis()` client initialization
3. Replace hand-built `HSET` command string with `self._client.hset(cache_key, update.field, update.value)`

The `socket_connect_timeout=2` parameter preserves the original 2-second timeout behavior. The `decode_responses=True` parameter ensures string values are returned as Python strings rather than bytes.

## Behaviour changes

**Before:** Raw socket writes concatenated untrusted values into command text; Redis server parsed each line as a separate command.

**After:** Each argument is framed separately with RESP protocol length prefix; Redis server processes them as atomic arguments to a single `HSET` command.

**Impact on legitimate use:** None. The `.hset()` method produces the same result as the hand-built command for all valid inputs. Values containing spaces, newlines, or Redis command names are now stored literally rather than parsed as separate commands.

**Testing:** Inject `\r\nFLUSHALL\r\n` in the display_name field and verify it is stored as literal data in the hash field, not executed as a separate command. The fix closes the injection vector while preserving all legitimate functionality.

**Sink contract check:**
- Returns: `redis.Redis.hset()` returns the number of fields added to the hash (0 or 1). The original code ignored the return value; this is unchanged.
- Arguments: The original code implicitly concatenates all three components; the fixed code passes each as a discrete framed value. Protocol-level safety is improved without changing application semantics.
- Error behaviour: redis-py connection errors are raised as exceptions; the original code would raise `socket` errors. Both are network-level failures handled by the same layer.

**Syntax verification:** Python compilation check passed.

**Import verification:** `redis.Redis` and `.hset()` method are part of redis-py standard library, widely maintained, and explicitly named in CWE-77 Python guidance as the correct remediation pattern.
