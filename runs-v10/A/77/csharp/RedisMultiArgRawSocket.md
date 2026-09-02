## Verdict

Command injection vulnerability confirmed. The code concatenates untrusted user input (`agentNote`) directly into a Redis protocol string without any escaping, allowing an attacker to inject arbitrary Redis commands via newline and space characters.

## Source

The vulnerability is at line 29, where unsanitized `agentNote` from the form is embedded into the command string via string concatenation (lines 21-25). If `agentNote` contains `\r\n` followed by Redis commands, the injected commands execute as separate operations.

Example attack: if `agentNote = "note\r\nFLUSHALL\r\n"`, the resulting payload sends both the HSET and a FLUSHALL command to Redis.

## Fix

Replace string concatenation with Redis Serialization Protocol (RESP) format, which uses explicit length-prefixed arguments that prevent injection:

```csharp
public void SaveAgentNote(string sessionId, string agentNote)
{
    long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    
    // Build RESP array: *7\r\n$4\r\nHSET\r\n$...\r\n...\r\n
    var parts = new[] { "HSET", $"session:{sessionId}", "note", agentNote, "updated", updatedAt.ToString() };
    var respCommand = BuildRespArray(parts);
    
    byte[] payload = Encoding.ASCII.GetBytes(respCommand);
    _redisSocket.Send(payload);
}

private string BuildRespArray(string[] elements)
{
    var sb = new StringBuilder();
    sb.Append($"*{elements.Length}\r\n");
    foreach (var element in elements)
    {
        sb.Append($"${Encoding.ASCII.GetByteCount(element)}\r\n");
        sb.Append(element);
        sb.Append("\r\n");
    }
    return sb.ToString();
}
```

## Explanation

RESP format uses `$<length>\r\n<data>\r\n` for each argument, where length is in bytes. This encoding makes the argument boundaries unambiguous and immune to embedded newlines or special characters—they become literal bytes within the length-prefixed field, not protocol delimiters. An attacker cannot inject commands because the `\r\n` inside an argument value is counted as part of its byte length, not as a line terminator.

The fix also eliminates the raw socket vulnerability class by using a well-defined protocol that enforces serialization of arguments independently of their content.
