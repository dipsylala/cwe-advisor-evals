## Verdict

Confirmed. `RedisCommandRelay.write_profile_field` builds a Redis inline-protocol command by concatenating an attacker-controlled value directly into the command text, then sends it raw over the socket. A `display_name` containing `\r\n` lets the caller terminate the intended `HSET` command and append arbitrary additional Redis commands (e.g. `FLUSHALL`, `CONFIG SET`, `EVAL ...`), which the server will execute as if they were sent by the application.

## Source

`display_name` in the JSON body of `POST /profile/display-name` (`profile_controller.py:update_display_name`), passed unmodified to `ProfileService.update_display_name` (`profile_service.py`), which wraps it in a `ProfileUpdate` DTO and passes it to `RedisCommandRelay.write_profile_field` (`redis_command_relay.py`). There is no validation or encoding anywhere on this path before the value is concatenated into the command string at line 20 and written to the socket.

## Fix

### File: redis_command_relay.py
```python
"""Thin client that speaks the Redis inline command protocol directly."""
import socket


class RedisCommandRelay:
    """Hand-rolled Redis client used for lightweight cache writes."""

    def __init__(self, host: str, port: int):
        self._sock = socket.create_connection((host, port), timeout=2)

    def write_profile_field(self, update):
        """Write a single profile field into the user's cache hash.

        Builds the command using the Redis RESP array protocol (each
        argument is sent as a length-prefixed bulk string) instead of
        concatenating values into a delimiter-based inline command. RESP
        bulk strings carry their own byte length, so a value containing
        CR, LF, or spaces is transmitted as literal data in that single
        argument and cannot be interpreted as a command separator or the
        start of a new command - unlike the inline protocol, which parses
        commands on whitespace and newlines.
        """
        cache_key = f"profile:{update.user_id}"
        command = self._encode_resp("HSET", cache_key, update.field, update.value)
        self._sock.sendall(command)

    @staticmethod
    def _encode_resp(*args) -> bytes:
        """Encode args as a RESP array of bulk strings (the format redis-py
        and other real Redis clients use for commands with argument
        values)."""
        parts = [f"*{len(args)}\r\n".encode("utf-8")]
        for arg in args:
            arg_bytes = arg.encode("utf-8") if isinstance(arg, str) else arg
            parts.append(f"${len(arg_bytes)}\r\n".encode("utf-8"))
            parts.append(arg_bytes)
            parts.append(b"\r\n")
        return b"".join(parts)
```

## Explanation

The original code used Redis's legacy inline command protocol, which splits a command into arguments on whitespace and terminates it on `\r\n`. Because `update.value` (the caller-supplied `display_name`) was interpolated into that text unescaped, any CR, LF, or extra whitespace in the value let an attacker smuggle additional arguments or entirely separate commands into the stream sent to the cache server.

The fix keeps the hand-rolled client (no new dependency) but switches the wire encoding from the inline protocol to RESP's length-prefixed bulk-string array format - the same format `redis-py` and other real Redis clients use to send commands. Each argument is preceded by its exact byte length, so the Redis server reads exactly that many bytes as the argument's value regardless of what characters it contains; embedded `\r\n` or spaces are just data within that one argument, not protocol syntax, so the injected content can no longer terminate the command or start a new one. This is a structural fix at the sink rather than a value-based filter, so it does not need to enumerate or strip any particular characters and does not risk mangling a legitimate display name that happens to contain them.
