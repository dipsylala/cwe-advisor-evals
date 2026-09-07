# CWE-77 Fix Report: MultiFileRedisCommandRelay

## Verdict

**Exploitable**

The untrusted `display_name` parameter flows from the HTTP request handler through the service layer to the Redis command builder without sanitization. The raw socket implementation concatenates user input directly into a Redis inline protocol command string, allowing an attacker to inject CRLF sequences that break the current command and execute arbitrary Redis commands.

Attack vector: sending `display_name: "test\r\nDEL *"` results in two commands being sent to Redis:
```
HSET profile:user123 display_name test
DEL *
```

## Source

- **CWE ID**: CWE-77 (Improper Neutralization of Special Elements used in a Command)
- **File**: evals/cases/77/python/MultiFileRedisCommandRelay/redis_command_relay.py
- **Line**: 20
- **Data source**: HTTP request parameter `display_name` in profile_controller.py, threaded through:
  - profile_controller.py line 19: `display_name = payload.get("display_name")`
  - profile_controller.py line 24: passed to `_service.update_display_name(user_id=str(user_id), display_name=display_name)`
  - profile_service.py line 27: `ProfileUpdate(user_id=user_id, field="display_name", value=display_name)`
  - profile_service.py line 32: `self._relay.write_profile_field(update)`
  - redis_command_relay.py line 18: `command = f"HSET {cache_key} {update.field} {update.value}\r\n"` (unsafe interpolation)
  - redis_command_relay.py line 20: `self._sock.sendall(command.encode("utf-8"))` (SINK)

## Fix

### Vulnerable Code (redis_command_relay.py)

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
        # VULNERABLE: untrusted update.value is concatenated into command string
        self._sock.sendall(command.encode("utf-8"))
```

### Fixed Code (redis_command_relay.py)

```python
"""Redis client using redis-py for parameterized command execution."""
import redis


class RedisCommandRelay:
    """Redis client for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._redis = redis.Redis(host=host, port=port, decode_responses=True, socket_connect_timeout=2)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's parameterized hset() method, which passes each
        argument as a separately framed RESP bulk string, preventing
        delimiter injection.
        """
        cache_key = f"profile:{update.user_id}"
        self._redis.hset(cache_key, update.field, update.value)
```

### Library Recommendation

- **Library**: `redis` (redis-py)
- **Minimum safe version**: Use the latest stable version from PyPI. Verify through SCA/dependency-check tooling before merging.
- **Why**: redis-py's `.hset()` method encodes each argument as a separate RESP bulk string with an explicit length prefix. When a value contains `\r\n`, spaces, or Redis command names, it is transmitted with its length so the server interprets it as literal data, not a command boundary or a new command.

## Explanation

The original code hand-builds Redis commands by concatenating strings, using the plain-text inline protocol. The inline protocol reads space-separated tokens on each line, treating `\r\n` as a command terminator. An attacker can inject `\r\n` to end the current command and start a new one.

The fix replaces the raw socket and string-building approach with redis-py's `redis.Redis` client and its parameterized `.hset()` method. The client internally uses the RESP (REdis Serialization Protocol) protocol, which encodes each argument as a bulk string with an explicit byte-length prefix:
```
*3\r\n$4\r\nHSET\r\n$16\r\nprofile:user123\r\n$12\r\ndisplay_name\r\n$15\r\ntest\r\nFLUSHALL\r\n\r\n
                                                                                              └─ value with embedded \r\n, transmitted with explicit length prefix
```

Because each argument includes its length, embedded delimiters and newlines cannot escape the value or be misinterpreted as command structure. This is the primary defence identified in the CWE-77 Python guidance.

Additional hardening (optional, for defence-in-depth):
- Restrict `update.field` to a whitelist of allowed field names (e.g., `display_name`, `bio`, `avatar_url`) so an attacker cannot write to unexpected keys.
- Validate `update.value` length and character set before sending (e.g., display names are under 256 characters and contain only printable Unicode).
- Use Redis ACL to restrict the application's connection to HSET operations only, excluding keyspace-wide commands like FLUSHALL or FLUSHDB.

## Behaviour Changes

| Change | Reason |
|--------|--------|
| Replaced `socket.create_connection()` with `redis.Redis()` | redis-py abstracts the wire protocol, eliminating raw string building as a source of injection vulnerabilities. |
| Replaced `socket.sendall(command.encode(...))` with `self._redis.hset()` | hset() is redis-py's parameterized API for hash field updates; each argument is separately framed in RESP format. |
| Removed manual `timeout=2` socket parameter | Moved to redis-py constructor parameter `socket_connect_timeout=2` for equivalent behaviour. |
| Removed manual CRLF terminator (`\r\n`) | redis-py's RESP encoder handles protocol framing automatically. |
| Added `decode_responses=True` | Ensures return values from redis-py are decoded as strings rather than bytes, maintaining compatibility with downstream code if the return value is ever used (currently it is ignored, but this is a defensive choice). |

All three files in the call chain (profile_controller.py, profile_service.py, profile_service.py) remain unchanged—the fix is localized to the RedisCommandRelay class. No changes to method signatures, return values, or the overall flow are required.

### No signature changes
- `write_profile_field(self, update)` signature unchanged
- The method still accepts the same `update` object with `user_id`, `field`, and `value` attributes
- The method returns `None` in both versions (redis-py's `.hset()` returns the number of fields added, but the original code ignored the socket's return value, and the calling code in profile_service.py also does not use any return value)

### Verification

Applied the fixed code to a Python 3.8+ environment with redis-py installed:
```bash
python -m py_compile redis_command_relay.py  # No syntax errors
python -c "import redis; from redis_command_relay import RedisCommandRelay; r = RedisCommandRelay('localhost', 6379)"  # Import succeeds with redis-py available
```

The fixed code:
- Syntax is valid for Python 3.8+ (redis-py is compatible with Python 3.7+)
- All new symbols (`redis.Redis`) are from the redis-py package (a well-maintained, OSI-approved BSD-licensed library on PyPI)
- Method signatures and return values are compatible with the existing call sites in profile_service.py

### Assumptions

- Assumed `display_name` is attacker-controlled and flows from the HTTP request without prior validation (confirmed by reading profile_controller.py lines 17-24, where it is extracted directly from the request body with only a presence check)
- Assumed the inline protocol vulnerability is the primary finding (the raw socket + f-string pattern is explicitly noted in the SAST report and matches CWE-77's Python guidance for hand-built Redis commands)
- redis-py is a widely used, maintained third-party library (confirmed available on PyPI under the name `redis`; minimum safe version must be verified against SCA/dependency-check tooling before merging)
