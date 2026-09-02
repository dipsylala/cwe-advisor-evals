## Verdict
Confirmed CWE-77 (Command Injection).

## Source
Line 21: The `statusMessage` parameter from an HTTP POST request is treated as trusted.

## Fix
Encode the Redis command using RESP (Redis Serialization Protocol) bulk string format, which uses length-prefixed strings that encapsulate special characters and prevent interpretation as command delimiters:

```csharp
[HttpPost("status")]
public IActionResult UpdateStatus(string userId, [FromForm] string statusMessage)
{
    if (string.IsNullOrEmpty(userId))
        return BadRequest("Missing userId");

    string redisKey = "presence:" + userId;
    
    // Encode using RESP protocol (length-prefixed bulk strings)
    int keyLength = Encoding.ASCII.GetByteCount(redisKey);
    int valueLength = Encoding.ASCII.GetByteCount(statusMessage);
    
    string command = $"*3\r\n$3\r\nSET\r\n${keyLength}\r\n{redisKey}\r\n${valueLength}\r\n{statusMessage}\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    _redisSocket.Send(payload);

    return Ok();
}
```

## Explanation
The original code concatenates `statusMessage` directly into the command string, allowing an attacker to inject newlines and additional Redis commands. For example, `statusMessage = "hello\r\nDEL somekey"` would execute both SET and DEL commands.

The fix uses RESP bulk string format: each value is prefixed with its byte length (`$length\r\nvalue\r\n`). This encapsulation ensures that special characters in `statusMessage`—including newlines and spaces—are treated as data, not protocol syntax. The Redis server reads the specified number of bytes and treats them as a single opaque value, preventing command injection regardless of the content.
