## Verdict

CONFIRMED. The code is vulnerable to command injection through the Redis inline protocol.

## Source

The vulnerability originates in the call chain:

1. **AnnotationsController.cs:18** — `AddAnnotation` receives untrusted `documentId` and `noteText` from HTTP form input
2. **AnnotationService.cs:15** — `SaveAnnotation` passes these directly to cache layer
3. **AnnotationCacheClient.cs:15-16** — `StoreAnnotation` constructs key as `"annotation:" + record.DocumentId` and value as timestamp + "|" + record.Text
4. **RedisWireWriter.cs:19** — `SendSetCommand` concatenates user-controlled key and value into a Redis inline protocol command without validation

The sink is at **RedisWireWriter.cs:24**, where the unsanitized command is written to the Redis wire.

## Fix

### File: RedisWireWriter.cs

```csharp
using System;
using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    // Writes commands directly to a Redis instance using the plain-text inline protocol,
    // bypassing StackExchange.Redis's RESP framing.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            // Validate that key and value do not contain Redis command separators
            // that would allow injection in the inline protocol
            if (key == null || key.Contains("\r") || key.Contains("\n"))
            {
                throw new ArgumentException("Key cannot be null or contain newline characters");
            }
            if (value == null || value.Contains("\r") || value.Contains("\n"))
            {
                throw new ArgumentException("Value cannot be null or contain newline characters");
            }

            string command = "SET " + key + " " + value + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);
        }
    }
}
```

## Explanation

The Redis inline protocol uses `\r\n` as a command delimiter. An attacker can inject arbitrary Redis commands by including `\r\n` in the key or value parameters. For example:

- **documentId**: `"doc1\r\nDEL * "`
- **Key constructed**: `"annotation:doc1\r\nDEL * "`
- **Command sent**: `"SET annotation:doc1\r\nDEL * value\r\n"`

Redis would parse this as two separate commands: `SET annotation:doc1` and `DEL *`, allowing deletion of all keys.

The fix validates that neither the key nor value contains carriage return or newline characters before constructing the command. This prevents command injection by rejecting any input that could break out of the intended command format. The validation is placed in the `SendSetCommand` method at the point where these untrusted values are about to be used in command construction.

Validation at the sink (rather than at the controller level) ensures defense-in-depth: even if `SendSetCommand` is called from other contexts with different input sources, the protection remains in place.
