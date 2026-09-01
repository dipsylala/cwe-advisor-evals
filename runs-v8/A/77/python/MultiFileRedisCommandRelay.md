## Verdict
CWE-77 confirmed. The `display_name` parameter flows from the HTTP request (profile_controller.py) through the service layer (profile_service.py) into the cache tier (redis_command_relay.py line 18-20). The value is concatenated directly into a Redis inline command without escaping, allowing an attacker to inject arbitrary Redis commands via newlines or spaces in the field value.

## Source
Line 18-20 of redis_command_relay.py:
```python
command = f"HSET {cache_key} {update.field} {update.value}\r\n"
self._sock.sendall(command.encode("utf-8"))
```

The `update.value` originates from user-supplied `display_name` in the HTTP request payload (profile_controller.py line 19) and reaches this sink without validation or escaping.

## Fix
Replace the inline command protocol with the Redis Serialization Protocol (RESP), which uses length-prefixed binary encoding and is injection-safe:

```python
def write_profile_field(self, update):
    """Write a single profile field into the user's cache hash.

    Uses RESP format for binary-safe command transmission.
    """
    cache_key = f"profile:{update.user_id}"
    
    # RESP array: [HSET, cache_key, field, value]
    command_parts = ["HSET", cache_key, update.field, update.value]
    resp_command = self._build_resp_array(command_parts)
    self._sock.sendall(resp_command)

def _build_resp_array(self, items):
    """Build a RESP array from a list of strings."""
    resp = f"*{len(items)}\r\n".encode("utf-8")
    for item in items:
        item_bytes = item.encode("utf-8")
        resp += f"${len(item_bytes)}\r\n".encode("utf-8")
        resp += item_bytes + b"\r\n"
    return resp
```

## Explanation
The inline Redis protocol treats spaces and newlines as command delimiters, making it inherently vulnerable to injection. RESP (Redis Serialization Protocol) uses length-prefixed binary encoding where each string value is preceded by its byte length (`$N`), preventing any content from being interpreted as command syntax. An attacker-supplied value containing `\r\nSET malicious:key pwned` becomes a counted byte sequence within the array element, not a command separator. This approach is binary-safe, requires no escaping, and is the standard method used by all production Redis clients.
