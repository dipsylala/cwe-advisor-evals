## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-77 (Improper Neutralization of Special Elements used in a Command)
- **Location**: `redis_command_relay.py`, `RedisCommandRelay.write_profile_field`, line 20 (`self._sock.sendall(command.encode("utf-8"))`)
- **Sink**: a hand-built Redis inline-protocol command sent over a raw `socket`
- **Interpreter**: Redis's plain-text inline command protocol (not an OS shell, so CWE-77 rather than CWE-78 applies)

## Source

- `profile_controller.py`, `update_display_name()`: `payload = request.get_json(force=True) or {}`; `user_id = payload.get("user_id")` and `display_name = payload.get("display_name")` are read directly from the untrusted HTTP request body, coerced (`str(user_id)`) but not otherwise validated, and passed to `_service.update_display_name(user_id=..., display_name=...)`.
- `profile_service.py`, `ProfileService.update_display_name()`: wraps both values unchanged into a `ProfileUpdate(user_id=user_id, field="display_name", value=display_name)` and calls `self._relay.write_profile_field(update)`. `field` is a hardcoded literal, not tainted.
- `redis_command_relay.py`, `RedisCommandRelay.write_profile_field()`: builds `cache_key = f"profile:{update.user_id}"` and `command = f"HSET {cache_key} {update.field} {update.value}\r\n"` by string interpolation, then sends the raw bytes with `self._sock.sendall(...)`.

Both `update.user_id` and `update.value` reach the sink unsanitized. Because the command is assembled as inline-protocol text terminated by `\r\n`, either field can carry an embedded `\r\n` (or, for `value`, embedded whitespace splitting it into extra tokens) to close the `HSET` command and start a new one, or to shift the argument count so the value is parsed as a different command entirely - e.g. a `display_name` of `bob\r\nFLUSHALL\r\n` injects a second command onto the connection. This is a genuine path: the value is external, reaches the sink with no delimiter neutralization, and the sink is a real command-interpreter boundary.

## Fix

### File: redis_command_relay.py

```python
"""Thin client that speaks to Redis via the redis-py client library."""
import redis


class RedisCommandRelay:
    """Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, socket_timeout=2)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's parameterized HSET so each value is framed as its
        own RESP argument and cannot be read as a separate command.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

**Library recommendation**: `redis` (redis-py), the maintained client library the knowledge base names for this pattern. The loaded guidance carries no minimum-safe-version floor for this case (the issue is a protocol-injection design flaw, not a specific CVE), so no version number is supplied here - confirm the resolved version against SCA/dependency-check tooling before merging, and prefer the current stable release from PyPI.

**Code change**: the hand-rolled socket client is replaced with `redis.Redis`, and the raw f-string `HSET ...` command line is replaced with the client's `.hset(name, key, value)` method. redis-py encodes each argument (`cache_key`, `update.field`, `update.value`) as a length-prefixed RESP bulk string before sending it, so an embedded `\r\n`, space, or command name inside any argument is delivered to Redis as literal byte content of that argument - it cannot terminate the current command or start a new one, because framing no longer depends on delimiter characters in the text. The command verb (`HSET`) is now the literal method call itself rather than a token parsed out of untrusted-adjacent text, closing off command-substitution as well as the CRLF-splitting path. `update.field` is not attacker-controlled (`ProfileService` hardcodes it to `"display_name"`), but `cache_key` and `update.value` are, and both are now passed as separate framed arguments rather than concatenated into the command string.

## Behaviour changes

- **Connection object**: `self._sock` (a raw `socket.socket`) is replaced by `self._client` (a `redis.Redis` instance). Any other code in the class or a subclass that referenced `self._sock` directly would break; nothing in the provided files does so - `write_profile_field` is the only method shown, and it is updated to match.
- **Timeout preserved**: the original `socket.create_connection(..., timeout=2)` becomes `redis.Redis(..., socket_timeout=2)`, keeping the same 2-second bound rather than substituting a different default.
- **Return value**: `hset()` returns an `int` (count of new fields added to the hash) instead of `sendall()`'s `None`. The call site discards this return value exactly as it discarded `sendall()`'s, so no new information is surfaced to the caller.
- **Failure behaviour differs in exception type**: the original raised `socket.error`/`OSError` on a connection problem; the redis-py client raises `redis.exceptions.ConnectionError` (or a similar `redis.exceptions.RedisError` subclass) instead. Neither `profile_service.py` nor `profile_controller.py` catches an exception from this call today, so this is a latent difference only if a caller is later added that catches the old exception type specifically.
- **Connection lifecycle**: `redis.Redis` lazily manages a connection pool rather than opening one TCP connection eagerly in `__init__`. The constructor no longer raises immediately on an unreachable host; the first command (`hset`) does instead. No caller in the provided files depends on `__init__` failing eagerly.

**Verification**: the fixed file was written to a scratch location outside the repository and checked with `python -m py_compile` - it compiled with no errors and no output. `redis.Redis` and `.hset()` are the standard redis-py client class and method named in the loaded guidance; `hset(name, key, value)` matches redis-py's documented signature. The `redis` package itself was not importable in this environment, so the import was verified by name/signature against the knowledge-base guidance rather than by an actual `import redis`.

**Assumptions**: none needed for CWE/language resolution - the CWE number, file, and language were unambiguous, and the fix follows the knowledge base's Python-specific guidance directly.
