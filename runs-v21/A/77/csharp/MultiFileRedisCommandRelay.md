## Verdict

**Confirmed CWE-77 Command Injection.** The vulnerability is in `RedisWireWriter.SendSetCommand()`, which constructs a Redis inline protocol command by string concatenation without escaping. User-controlled `noteText` from the HTTP controller flows through the service layer to the cache client and into the command string. Because the inline protocol uses spaces and `\r\n` as delimiters, an attacker can inject arbitrary Redis commands by including these characters in their input.

## Source

The call chain routes user input to the vulnerable sink:
1. `AnnotationsController.AddAnnotation()` receives `noteText` as form data
2. Passes to `AnnotationService.SaveAnnotation()`
3. Which passes to `AnnotationCacheClient.StoreAnnotation()`
4. Which calls `RedisWireWriter.SendSetCommand(key, value)` with the user text in the value
5. Line 19 of `RedisWireWriter.cs` constructs: `"SET " + key + " " + value + "\r\n"` without escaping
6. Line 24 sends this string directly to Redis via the raw TCP socket

An attacker can inject commands by setting `noteText` to a value like `x\r\nDEL *\r\n`, which results in the Redis server receiving and executing both a SET and a DELETE command.

## Fix

### File: RedisWireWriter.cs

```csharp
using System;
using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to a Redis instance using the RESP protocol,
    // properly encoding arguments to prevent command injection.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            // Build a RESP command: *3\r\n$3\r\nSET\r\n$<key_len>\r\n<key>\r\n$<value_len>\r\n<value>\r\n
            // This encoding makes the command structure unambiguous: arguments are prefixed with their byte length,
            // so special characters (spaces, newlines) in the value cannot break out of the argument boundary.
            
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] valueBytes = Encoding.UTF8.GetBytes(value);
            
            StringBuilder commandBuilder = new StringBuilder();
            commandBuilder.Append("*3\r\n");
            commandBuilder.Append("$3\r\n");
            commandBuilder.Append("SET\r\n");
            commandBuilder.Append("$").Append(keyBytes.Length).Append("\r\n");
            
            byte[] keyPart = Encoding.UTF8.GetBytes(commandBuilder.ToString());
            
            commandBuilder.Clear();
            commandBuilder.Append("$").Append(valueBytes.Length).Append("\r\n");
            byte[] valueLengthPart = Encoding.UTF8.GetBytes(commandBuilder.ToString());
            
            byte[] terminator = Encoding.UTF8.GetBytes("\r\n");
            
            NetworkStream stream = _client.GetStream();
            
            // Write RESP frame parts
            stream.Write(keyPart, 0, keyPart.Length);
            stream.Write(keyBytes, 0, keyBytes.Length);
            stream.Write(terminator, 0, terminator.Length);
            stream.Write(valueLengthPart, 0, valueLengthPart.Length);
            stream.Write(valueBytes, 0, valueBytes.Length);
            stream.Write(terminator, 0, terminator.Length);
        }
    }
}
```

## Explanation

The original code used Redis's inline protocol, which is fundamentally unsafe for untrusted input because it interprets spaces and newlines as syntax. The fix switches to RESP (Redis Serialization Protocol) framing, which is the protocol Redis actually uses internally and which the client library normally uses.

In RESP, each argument is prefixed with its byte length: `$<length>\r\n<data>\r\n`. This length prefix means that special characters in the value—including spaces, newlines, or any other character—are treated as literal bytes, not as command syntax. An attacker cannot inject additional commands because the Redis server will read exactly `<length>` bytes for the value, regardless of what those bytes contain.

For example, if `noteText` is `x\r\nDEL *`, the value argument becomes `$10\r\nx\r\nDEL *\r\n`, and Redis will read exactly 10 bytes for that argument, treating the newline and DEL as part of the data string, not as a command boundary. This closes the injection vector entirely.
