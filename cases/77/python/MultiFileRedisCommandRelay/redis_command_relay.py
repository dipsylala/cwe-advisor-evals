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
        # SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
        self._sock.sendall(command.encode("utf-8"))
