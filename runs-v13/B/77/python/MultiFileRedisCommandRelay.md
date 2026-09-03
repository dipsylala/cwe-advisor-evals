## Verdict

Exploitable. Untrusted input (display_name) from the HTTP request body is threaded through the service layer into a hand-built Redis inline protocol command string without any neutralization of the protocol's special characters (CRLF, spaces, command names). An attacker can inject arbitrary Redis commands by including `\r\n` or command keywords in the display_name value.

## Source

HTTP request body parameter: `profile_controller.py` line 19 `display_name = payload.get("display_name")`

Data flow: `display_name` → `ProfileService.update_display_name()` → `ProfileUpdate.value` → `RedisCommandRelay.write_profile_field()` → string concatenation into inline command → `socket.sendall()` at line 20

## Fix

Replace the hand-built Redis inline command with redis-py's parameterized `.hset()` API, which frames each argument with an explicit RESP bulk-string length prefix, preventing embedded delimiters from being interpreted as command separators.

**Vulnerable code** (redis_command_relay.py):
```python
def write_profile_field(self, update):
    cache_key = f"profile:{update.user_id}"
    command = f"HSET {cache_key} {update.field} {update.value}\r\n"
    # SAST FINDING: CWE-77 injection sink at line 20
    self._sock.sendall(command.encode("utf-8"))
```

**Fixed code**:
```python
import redis

class RedisCommandRelay:
    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, decode_responses=True)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash."""
        cache_key = f"profile:{update.user_id}"
        # Parameterized call: each argument is framed as a RESP bulk string
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The vulnerability exists because the code constructs a Redis inline command by f-string concatenation, which interprets the plain-text protocol's CRLF as command delimiters. A value like `\r\nFLUSHALL\r\n` becomes two separate commands: the intended HSET, followed by FLUSHALL. The redis-py library encodes each argument as a RESP bulk string with an explicit byte-count prefix (e.g., `$5\r\nworld\r\n` for the value "world"), so embedded newlines and spaces are treated as literal data, not delimiters. This prevents an attacker from injecting additional commands via the field or value arguments.

## Behaviour changes

- **Connection model**: Raw socket connection replaced with redis-py connection pool. The original code relied on a persistent socket (`self._sock`) held open across calls; redis-py manages connection pooling and reuse automatically, which is safer and more efficient.
- **Error handling**: Socket exceptions (`socket.timeout`, `BrokenPipeError`) are replaced with redis-py exceptions (`redis.ConnectionError`, `redis.ResponseError`). Callers must catch the new exception types; generic exception handlers will still catch both.
- **Return value**: The original `sendall()` returns `None`; redis-py's `.hset()` returns the number of fields added (0 if the field existed and was overwritten, 1 if new). The current code ignores the return, so callers see no difference.
- **Implicit default arguments**: The original socket has an implicit 2-second timeout; `redis.Redis` defaults to no timeout (blocking indefinitely). If the timeout is required for production stability, pass `socket_connect_timeout=2` and `socket_keepalive_options={...}` to `redis.Redis()`.
