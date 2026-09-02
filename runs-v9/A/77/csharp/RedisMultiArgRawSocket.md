## Verdict

Confirmed. `SaveAgentNote` builds a Redis inline command by concatenating unvalidated `agentNote` into a plain-text string and writes it straight to the socket. Redis's inline command format splits arguments on whitespace and terminates the command on `\r\n`, so any space, CR, or LF the caller places in `agentNote` is interpreted by Redis as a token/command boundary rather than literal note text.

## Source

`agentNote` in `SessionNoteWriter.SaveAgentNote(string sessionId, string agentNote)` (`RedisMultiArgRawSocket.cs`, line 18) — per the adjacent comment, this value comes straight from the support ticket form and is never validated.

## Fix

Replace the hand-built inline command with proper RESP (REdis Serialization Protocol) multi-bulk framing, where each argument is length-prefixed instead of delimited by whitespace/CRLF. Length-prefixing means the byte length is declared up front, so embedded spaces or CR/LF bytes inside `agentNote` are just payload bytes and can never be reinterpreted as a new argument or a new command.

```csharp
using System;
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

            string[] args =
            {
                "HSET",
                "session:" + sessionId,
                "note",
                agentNote,
                "updated",
                updatedAt.ToString()
            };

            byte[] payload = BuildRespCommand(args);
            _redisSocket.Send(payload);
        }

        // Encodes a Redis command using RESP multi-bulk framing (*<count>\r\n
        // followed by $<byte-length>\r\n<data>\r\n per argument). Because each
        // argument is delimited by an explicit byte length rather than by
        // whitespace or CRLF, no value can inject extra arguments or
        // additional commands regardless of its content.
        private static byte[] BuildRespCommand(string[] args)
        {
            var sb = new StringBuilder();
            sb.Append('*').Append(args.Length).Append("\r\n");

            var buffer = new System.IO.MemoryStream();
            byte[] header = Encoding.UTF8.GetBytes(sb.ToString());
            buffer.Write(header, 0, header.Length);

            foreach (string arg in args)
            {
                byte[] argBytes = Encoding.UTF8.GetBytes(arg);
                byte[] argHeader = Encoding.UTF8.GetBytes(
                    "$" + argBytes.Length + "\r\n");
                buffer.Write(argHeader, 0, argHeader.Length);
                buffer.Write(argBytes, 0, argBytes.Length);
                byte[] trailer = Encoding.UTF8.GetBytes("\r\n");
                buffer.Write(trailer, 0, trailer.Length);
            }

            return buffer.ToArray();
        }
    }
}
```

If the project already depends on a maintained Redis client (e.g. `StackExchange.Redis`), prefer calling `IDatabase.HashSetAsync` (or equivalent) through that client instead of hand-rolling RESP framing — the client handles argument encoding and connection management, and removes this class of bug entirely along with the extra maintenance surface of a custom protocol encoder.

## Explanation

The original code built a Redis "inline command" — a single line of space-separated tokens terminated by `\r\n` — by string concatenation. Redis parses inline commands by splitting on whitespace, so if `agentNote` contains a space, it silently adds extra arguments to the `HSET` call; if it contains `\r\n`, everything after the newline is parsed as a brand-new Redis command sent over the same connection. An attacker who controls the support-ticket note field could therefore inject arbitrary Redis commands — for example appending a note like `x\r\nFLUSHALL\r\n` to run a second, unintended command, or `x\r\nCONFIG SET requirepass ...\r\n` to reconfigure the server — with no need to escape or encode anything beyond inserting a carriage return and line feed.

The fix removes the interpretation step. RESP multi-bulk encoding declares the exact byte length of each argument before the argument's bytes appear, so Redis reads exactly that many bytes as one opaque value no matter what those bytes contain. A space, CR, LF, or any other byte sequence inside `agentNote` is consumed as literal note content and cannot be reinterpreted as a delimiter, an extra argument, or the start of a new command. This is the same framing real Redis client libraries use internally, which is why switching to a maintained client is the more robust long-term option even though the raw-socket RESP encoder above closes the immediate injection.
