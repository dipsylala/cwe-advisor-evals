## Verdict
Confirmed. User-controlled input (`display_name`) from the HTTP request flows directly into a Redis command string without escaping, enabling command injection.

## Source
`display_name` originates from the request body in `profile_controller.py` line 19 (`payload.get("display_name")`), passes through `ProfileService.update_display_name()` in `profile_service.py` line 26-27 (packaged into `ProfileUpdate.value`), and reaches the sink in `redis_command_relay.py` line 18.

## Fix
Replace the inline Redis command construction with the redis-py library, which handles RESP protocol encoding automatically and prevents command injection:

```python
import redis

class RedisCommandRelay:
    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, socket_connect_timeout=2, decode_responses=True)

    def write_profile_field(self, update):
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

**Alternative (if redis-py is unavailable):** Use RESP protocol encoding instead of the inline command format. Encode values as bulk strings with proper length prefixes:

```python
def write_profile_field(self, update):
    cache_key = f"profile:{update.user_id}"
    # Encode as RESP bulk strings
    parts = [
        f"${len('HSET')}\r\nHSET\r\n",
        f"${len(cache_key)}\r\n{cache_key}\r\n",
        f"${len(update.field)}\r\n{update.field}\r\n",
        f"${len(update.value)}\r\n{update.value}\r\n"
    ]
    command = "".join(parts)
    self._sock.sendall(command.encode("utf-8"))
```

## Explanation
The vulnerability exists because the inline Redis protocol (used in the current code) concatenates field and value directly into the command string. Redis inline commands use whitespace and CRLF as delimiters, so an attacker controlling `display_name` can inject newlines and Redis commands. For example, setting `display_name` to `value\r\nFLUSHALL` would execute an unauthorized command.

The redis-py library uses the RESP (Redis Serialization Protocol) format, which encodes each argument's length explicitly, preventing injection regardless of the argument's content. RESP is the standard Redis protocol and is more robust than the inline format.

If the inline protocol must be retained, RESP bulk-string encoding (with explicit length prefixes like `$5\r\nhello\r\n`) protects against injection by preventing special characters from being interpreted as command delimiters.
