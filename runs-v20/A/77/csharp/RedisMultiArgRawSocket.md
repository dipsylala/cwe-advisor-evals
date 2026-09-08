## Verdict

Confirmed. `SaveAgentNote` builds a Redis inline command by string-concatenating unvalidated, attacker-controlled input directly into the command text, then writes the raw bytes to the Redis TCP socket. Because the command boundary is whitespace and the command terminator is `\r\n`, a support-ticket note containing either lets an attacker inject additional Redis arguments or entirely separate Redis commands (e.g. `FLUSHALL`, `CONFIG SET`, or overwriting other keys) onto the same connection.

## Source

`agentNote`, the second parameter of `SessionNoteWriter.SaveAgentNote(string sessionId, string agentNote)`. Per the existing comment, it "comes straight from the support ticket form and is never validated before this call," so it is fully attacker-controlled free text (can contain spaces, `\r`, `\n`, and arbitrary bytes).

## Fix

### File: RedisMultiArgRawSocket.cs

```csharp
using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

namespace SupportDesk.Sessions
{
    public class SessionNoteWriter
    {
        private readonly Socket _redisSocket;

        public SessionNoteWriter(Socket redisSocket)
        {
            _redisSocket = redisSocket;
        }

        // sessionId is a server-generated GUID; agentNote comes straight from
        // the support ticket form and is never validated before this call.
        public void SaveAgentNote(string sessionId, string agentNote)
        {
            long updatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            byte[] payload = BuildRespCommand(
                "HSET",
                "session:" + sessionId,
                "note",
                agentNote,
                "updated",
                updatedAt.ToString());

            _redisSocket.Send(payload);
        }

        // Encodes the command using Redis's RESP multibulk protocol - an
        // array of explicitly length-prefixed bulk strings - instead of a
        // single inline command string built by concatenation. Because each
        // argument is framed by its own byte length rather than by
        // whitespace or a line terminator, a value containing spaces, "\r",
        // "\n", or any other byte can never be parsed as an argument
        // separator or as the start of a second command; it is always
        // consumed as opaque data for the argument it belongs to.
        private static byte[] BuildRespCommand(params string[] args)
        {
            using (var stream = new MemoryStream())
            {
                WriteAscii(stream, "*" + args.Length + "\r\n");
                foreach (string arg in args)
                {
                    byte[] argBytes = Encoding.UTF8.GetBytes(arg);
                    WriteAscii(stream, "$" + argBytes.Length + "\r\n");
                    stream.Write(argBytes, 0, argBytes.Length);
                    WriteAscii(stream, "\r\n");
                }
                return stream.ToArray();
            }
        }

        private static void WriteAscii(Stream stream, string text)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(text);
            stream.Write(bytes, 0, bytes.Length);
        }
    }
}
```

## Explanation

The original code assembled a Redis "inline command" by hand: `"HSET session:" + sessionId + " note " + agentNote + " updated " + updatedAt + "\r\n"`. Redis's inline protocol splits a command into arguments on whitespace and ends it at `\r\n`. Since `sessionId` is a server-generated GUID it is safe, but `agentNote` is unvalidated user text, so:

- A space in `agentNote` splits it into extra arguments, changing what `HSET` stores (e.g. it could shift or add fields).
- A `\r\n` sequence in `agentNote` terminates the `HSET` command early and starts a brand-new command on the same connection, letting the attacker run arbitrary Redis commands (`FLUSHALL`, `CONFIG SET`, writes to other keys, etc.) with whatever privileges the application's Redis connection has.

The fix keeps the raw-socket transport (no new client library is introduced) but replaces the inline-command string with Redis's RESP multibulk array format: `*<argc>\r\n` followed by, for each argument, `$<byte-length>\r\n<argument-bytes>\r\n`. Every argument's length is computed and sent explicitly, so the receiving Redis server reads exactly that many bytes as the argument's value regardless of what they contain - embedded spaces, `\r`, `\n`, or arbitrary binary data are all treated as literal data, never as protocol structure. This is the same framing real Redis clients (e.g. StackExchange.Redis) use internally and is the standard way to send binary-safe arguments over the Redis wire protocol; it removes the injection primitive at the protocol level rather than attempting to blocklist or strip specific characters from the note text, which would risk silently corrupting legitimate notes that happen to contain a space or newline.
