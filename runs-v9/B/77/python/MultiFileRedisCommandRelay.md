## Verdict

- **CWE-77** - Improper Neutralization of Special Elements used in a Command ('Command Injection')
- **Location:** `redis_command_relay.py:20` (`self._sock.sendall(command.encode("utf-8"))`)
- **Verdict:** exploitable
- **Confidence:** high

## Source

- **Source:** `profile_controller.py:18-19` - `user_id` and `display_name` are read directly from the JSON request body of `POST /profile/display-name` with no validation beyond a truthiness check.
- **Path:** `profile_controller.update_display_name()` passes both values into `ProfileService.update_display_name(user_id, display_name)` (`profile_controller.py:24`) -> `ProfileService` wraps them in a `ProfileUpdate` DTO with the hardcoded field name `"display_name"` (`profile_service.py:27`) -> `ProfileService.update_display_name()` calls `self._relay.write_profile_field(update)` (`profile_service.py:32`) -> `RedisCommandRelay.write_profile_field()` builds `command = f"HSET {cache_key} {update.field} {update.value}\r\n"`, where `cache_key` embeds `update.user_id` and the trailing token is `update.value` (the attacker-controlled `display_name`) (`redis_command_relay.py:17-18`).
- **Sink:** `redis_command_relay.py:20` - the assembled string is sent verbatim over a raw TCP socket using Redis's plain-text inline command protocol. Neither `user_id` nor `display_name` is neutralized before concatenation, so a value containing a space or `\r\n` changes the token count or terminates the command early and starts a new one (e.g. a `display_name` of `x\r\nFLUSHALL\r\n` is interpreted by Redis as two separate commands). `update.field` is a hardcoded literal, not attacker-controlled, so it is not part of the exploitable path.
- Sink contract before the fix: `sendall()` returns `None` and its return value is unused by the caller; the code never reads a reply from the socket, so any Redis-level error (wrong type, unknown command, etc.) is silently discarded; the socket's timeout (`timeout=2`, set once in `__init__` via `socket.create_connection`) applies to the single persistent connection reused for every call; failures raise the underlying `OSError`, which is not caught anywhere in this chain and would propagate to the Flask request handler.

## Fix

**Library recommendation:** replace the hand-rolled socket protocol with `redis` (redis-py), which frames each argument as a length-prefixed RESP bulk string so embedded delimiters cannot be read as a new command. The loaded guidance does not carry a minimum safe version for this library; confirm the resolved version against SCA/dependency-check tooling before merging, and add it to the project's manifest (`requirements.txt`/`pyproject.toml`) if not already a dependency.

Vulnerable code (`redis_command_relay.py`):

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
        # SAST FINDING: CWE-77 reported here. Sink is the next statement.
        self._sock.sendall(command.encode("utf-8"))
```

Fixed code (`redis_command_relay.py`):

```python
"""Redis client used for lightweight cache writes."""
import redis


class RedisCommandRelay:
    """Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._client = redis.Redis(host=host, port=port, socket_timeout=2)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Uses redis-py's parameterized HSET call so the key, field, and
        value are each sent to the server as their own RESP-framed
        argument instead of being concatenated into a raw command string.
        """
        cache_key = f"profile:{update.user_id}"
        self._client.hset(cache_key, update.field, update.value)
```

## Explanation

The vulnerability was string concatenation building a raw Redis inline command (`f"HSET {cache_key} {update.field} {update.value}\r\n"`) sent directly over a socket, so any CR, LF, or whitespace inside `user_id` or `display_name` could terminate the intended command and inject a new one. The fix replaces the raw socket and hand-built command with `redis.Redis().hset(cache_key, field, value)`, which passes `cache_key`, `field`, and `value` as independent arguments; redis-py's client encodes each as a length-prefixed RESP bulk string, so a delimiter embedded in any of them is transmitted as literal argument bytes and cannot be parsed as a command boundary. `update.field` is a hardcoded literal (`"display_name"`) supplied by `ProfileService`, not attacker input, so no untrusted value occupies the command-name position, which is the one case redis-py's framing does not protect (per the loaded Python guidance, `pack_command` whitespace-splits `args[0]` before framing).

## Behaviour changes

- **Reply handling (new behaviour, not previously present):** the original code never read a response from the socket, so any Redis-side rejection (wrong type at `cache_key`, ACL denial, etc.) was silently swallowed. `redis.Redis.hset()` performs a synchronous request/response round trip and raises `redis.exceptions.ResponseError` (or `redis.exceptions.ConnectionError` on a transport failure) instead of failing silently. This surfaces errors that were previously invisible; callers of `write_profile_field()` that did not expect an exception from this call should be reviewed, though none currently catch or depend on its previous silent-failure behaviour.
- **Connection timing:** `socket.create_connection()` connected eagerly in `__init__`, so an unreachable Redis host raised immediately at `ProfileService` construction. `redis.Redis(...)` connects lazily on first command, so that same failure now surfaces on the first `write_profile_field()` call instead of at construction time.
- **Return value:** `sendall()` returned `None`; `hset()` returns an `int` (fields added). Neither return value is used by `write_profile_field()` or its caller, so this is not observable.
- **Everything else** (return-value usage, encoding, the effective 2-second socket timeout) is preserved: `encoding="utf-8"` is redis-py's default, matching the original explicit encode, and `socket_timeout=2` preserves the original's per-operation timeout intent.
