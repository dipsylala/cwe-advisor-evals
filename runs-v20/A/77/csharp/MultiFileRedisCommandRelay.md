## Verdict

Confirmed. `RedisWireWriter.SendSetCommand` builds a Redis command by concatenating raw, attacker-influenced strings into the Redis inline text protocol and writing the result directly to the TCP socket. Both the key (derived from the `documentId` route segment) and the value (the `noteText` form field, embedded with a `|` separator) reach this sink without any encoding that prevents them from being interpreted as protocol structure rather than data. A value or key containing a space breaks the inline protocol's argument splitting, and a value or key containing `\r\n` terminates the `SET` command and lets the attacker append arbitrary additional Redis commands (e.g. `FLUSHALL`, `CONFIG SET`, or a second `SET` that overwrites unrelated keys) that the server will execute in sequence.

## Source

`AnnotationsController.AddAnnotation(string documentId, [FromForm] string noteText)` in `AnnotationsController.cs` accepts both `documentId` (from the route) and `noteText` (from a submitted form field) directly from the HTTP request with no validation. Both flow unmodified through `AnnotationService.SaveAnnotation` into `AnnotationRecord.DocumentId` / `AnnotationRecord.Text`, then through `AnnotationCacheClient.StoreAnnotation`, which builds `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`, and passes both into `RedisWireWriter.SendSetCommand(key, value)` - the sink at `RedisWireWriter.cs` line 24, where they are concatenated into `"SET " + key + " " + value + "\r\n"` and written to the raw socket.

## Fix

### File: RedisWireWriter.cs
```csharp
using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    // Writes commands to Redis using the RESP (REdis Serialization Protocol) multi-bulk
    // wire format: every argument is framed by its own byte length, so bytes inside an
    // argument - including CR, LF, and spaces - are consumed as literal argument data
    // and can never be read as a command terminator or argument delimiter.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            byte[] payload = EncodeCommand("SET", key, value);

            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);
        }

        // Encodes a Redis command as a RESP array of bulk strings: *<argc>\r\n then, per
        // argument, $<byte length>\r\n<argument bytes>\r\n. Because each argument is
        // delimited by an explicit byte count rather than by whitespace or a line ending,
        // arbitrary attacker-controlled bytes inside an argument cannot inject additional
        // arguments or additional commands.
        private static byte[] EncodeCommand(params string[] args)
        {
            var builder = new StringBuilder();
            builder.Append('*').Append(args.Length).Append("\r\n");

            foreach (string arg in args)
            {
                int byteLength = Encoding.UTF8.GetByteCount(arg);
                builder.Append('$').Append(byteLength).Append("\r\n");
                builder.Append(arg).Append("\r\n");
            }

            return Encoding.UTF8.GetBytes(builder.ToString());
        }
    }
}
```

## Explanation

The root cause is not the missing validation on `documentId`/`noteText` but the wire format itself: Redis's inline protocol delimits arguments with whitespace and terminates a command with `\r\n`, so any string concatenated into it is simultaneously data and protocol control - a class of bug identical in shape to building a shell command line by string concatenation. Stripping or allowlisting characters out of the note text would be fragile (it changes the field's legitimate content, e.g. rejecting multi-line notes) and would still leave the door open wherever `documentId` or a future caller of `SendSetCommand` forgets to filter.

The fix instead changes how `RedisWireWriter` frames commands, mirroring the fix for shell/argv injection where an argument array replaces a concatenated command line. RESP's multi-bulk format prefixes each argument with its exact byte length (`$<len>\r\n<bytes>\r\n`), so Redis reads precisely that many bytes as the argument regardless of their content - an embedded `\r\n` or space is just data, not a delimiter. This is the same framing `StackExchange.Redis` uses internally (the file's own comment notes it is bypassing that library's RESP framing), so the fix brings the hand-rolled writer in line with the standard protocol rather than introducing a new one; no caller-visible behavior changes, since `SendSetCommand(key, value)` still issues a single `SET key value` command to Redis, just correctly framed. `Encoding.UTF8.GetByteCount` is used (rather than assuming one byte per char, as the prior ASCII-based length arithmetic effectively did) so the length prefix matches the actual number of bytes written for non-ASCII note text.

Verification: with a `noteText` of `x\r\nFLUSHALL\r\n`, the previous implementation wrote `SET annotation:<id> <ts>|x\r\nFLUSHALL\r\n\r\n` - two inline commands. With the fix, the same value is emitted as a length-prefixed bulk string (`$<n>\r\n<ts>|x\r\nFLUSHALL\r\n\r\n`) inside a single `*3\r\n...` array, which a RESP-speaking Redis server reads as one `SET` command with that entire string as its value argument, executing no injected command.
