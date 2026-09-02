## Verdict

Confirmed. `RedisCommandRelay.write_profile_field` builds a Redis command by string-concatenating attacker-controlled values into the Redis **inline command** protocol and writes the result straight to the socket. Because the inline protocol splits on whitespace and terminates a command on `\r\n`, any request-supplied value that contains a space or a CRLF sequence lets the caller inject extra Redis arguments or entirely separate Redis commands (e.g. `CONFIG SET`, `FLUSHALL`, or a `CONFIG SET dir` / `CONFIG SET dbfilename` / `SAVE` sequence used for RCE via a written webshell).

## Source

- HTTP entry point: `profile_controller.py`, `update_display_name()` — `display_name` (and `user_id`) is read directly from the parsed JSON request body (`payload.get("display_name")`, `payload.get("user_id")`) with no content validation beyond a not-empty check, then passed to `ProfileService.update_display_name`.
- Pass-through: `profile_service.py`, `ProfileService.update_display_name()` wraps the values in a `ProfileUpdate` DTO with no sanitization and calls `RedisCommandRelay.write_profile_field(update)`.
- Sink: `redis_command_relay.py`, line 18 builds `command = f"HSET {cache_key} {update.field} {update.value}\r\n"` (where `cache_key` also embeds `update.user_id`), and line 20 sends it raw with `self._sock.sendall(command.encode("utf-8"))`. Neither `user_id`, `field`, nor `value` is escaped or length-delimited before being placed in the command text.

## Fix

Replace the hand-rolled inline-protocol string with the RESP (REdis Serialization Protocol) multibulk encoding that real Redis clients use: every argument is sent as a length-prefixed bulk string, so the byte content of an argument (spaces, `\r`, `\n`, anything) is carried as opaque payload and can never be re-parsed as an argument or command boundary.

```python
"""Thin client that speaks the Redis inline command protocol directly."""
import socket


class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._sock = socket.create_connection((host, port), timeout=2)

    @staticmethod
    def _encode_command(*args):
        """Encode args as a RESP multibulk request.

        Each argument is length-prefixed rather than delimited by
        whitespace/CRLF, so arbitrary bytes inside an argument (including
        spaces and \r\n) cannot be interpreted as a separate argument or
        a separate command.
        """
        parts = [f"*{len(args)}\r\n".encode("utf-8")]
        for arg in args:
            arg_bytes = str(arg).encode("utf-8")
            parts.append(f"${len(arg_bytes)}\r\n".encode("utf-8"))
            parts.append(arg_bytes)
            parts.append(b"\r\n")
        return b"".join(parts)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash."""
        cache_key = f"profile:{update.user_id}"
        command = self._encode_command("HSET", cache_key, update.field, update.value)
        self._sock.sendall(command)
```

If a maintained client is an option, prefer replacing this hand-rolled socket layer with `redis-py` (`redis.Redis(...).hset(cache_key, update.field, update.value)`); it implements the same RESP encoding internally and removes the hand-rolled protocol code entirely, along with connection-handling concerns (retries, timeouts, pooling) this class doesn't address.

## Explanation

The vulnerability is not that `user_id`/`display_name` are unvalidated in the web-framework sense — it's that the relay serializes them into a protocol that uses plain-text delimiters (spaces between arguments, CRLF between commands) without escaping. That makes it a *command* injection into the Redis protocol: a `display_name` such as `x\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSAVE\r\n` is not one HSET call with a weird value, it's five distinct Redis commands, because the Redis server parses on the same delimiters the client failed to escape.

Switching to RESP fixes this structurally rather than by filtering: each argument is preceded by its exact byte length (`$<n>\r\n<n bytes>\r\n`), so the Redis parser reads exactly `n` bytes as the argument regardless of what those bytes are — a `\r\n` or space inside the value is just payload, not a delimiter. This is the same reason parameterized SQL queries close SQL injection: the fix separates the data channel from the command-structure channel instead of trying to enumerate and strip dangerous characters from the data. Stripping or blocklisting characters here would be weaker anyway, since a display name legitimately might contain spaces, and a denylist for CR/LF is easy to bypass with encoding differences the hand-rolled parser doesn't anticipate.

To verify the fix, send a `display_name` containing a literal `\r\n` followed by a second Redis command (captured via a mock socket, or observed with `redis-cli MONITOR` against a real instance) and confirm only a single `HSET` with the literal value (CRLF included) is executed — no second command should ever reach the server.
