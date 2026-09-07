## Verdict
CONFIRMED — Command injection vulnerability in Redis inline command construction.

## Source
Attacker-controlled `display_name` from HTTP request flows through `profile_controller.py` (line 24) → `ProfileService.update_display_name()` (line 26-32) → `RedisCommandRelay.write_profile_field()` (line 18) where it is concatenated directly into a Redis command without escaping.

Vulnerability chain: HTTP request body (`display_name`) → line 24 controller → line 27 ProfileUpdate constructor → line 18 command construction → line 20 socket send (sink).

## Fix

### File: redis_command_relay.py

```python
"""Thin client that speaks the Redis inline command protocol directly."""
import socket


class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._sock = socket.create_connection((host, port), timeout=2)

    def _escape_inline_arg(self, arg: str) -> str:
        """Escape a string for use in Redis inline protocol.

        Quotes the argument and escapes any internal quotes and backslashes.
        This prevents injection of protocol terminators (\r\n) or command separators.
        """
        # Escape backslashes first, then quotes, then wrap in quotes
        escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Builds the Redis inline command by hand instead of using redis-py,
        so the field value is concatenated straight into the command text.
        """
        cache_key = self._escape_inline_arg(f"profile:{update.user_id}")
        field = self._escape_inline_arg(update.field)
        value = self._escape_inline_arg(update.value)
        command = f"HSET {cache_key} {field} {value}\r\n"
        self._sock.sendall(command.encode("utf-8"))
```

## Explanation
The original code concatenated user-controlled `update.value` directly into the Redis inline command without escaping. In the Redis inline protocol, arguments are space-separated and terminated by `\r\n`. An attacker could inject newlines to terminate the current command and start a new one:

**Attack example:** If `display_name` is set to `test\r\nDEL profile:other_user`, the original code would send:
```
HSET profile:123 display_name test
DEL profile:other_user
```

The fix introduces `_escape_inline_arg()` which:
1. Escapes backslashes (`\` → `\\`) to prevent backslash-based bypasses
2. Escapes double quotes (`"` → `\"`) to prevent quote breakout
3. Wraps the result in double quotes

With the fix, the same malicious input is safely treated as a literal string value:
```
HSET "profile:123" "display_name" "test\r\nDEL profile:other_user"
```

The backslash-escaped quotes and the outer quotes ensure that any special characters (including `\r\n`, spaces, and delimiters) are interpreted as literal data rather than protocol syntax. All user-controlled components (`user_id`, `field`, `value`) are now properly escaped before being sent to Redis.
