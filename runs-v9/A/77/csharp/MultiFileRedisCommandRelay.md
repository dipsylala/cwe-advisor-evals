## Verdict

Confirmed. `RedisWireWriter.SendSetCommand` builds a Redis command by concatenating raw strings into the plain-text inline protocol and writes the result directly to the socket. Both the key and the value are attacker-influenced, and neither is validated or escaped before being placed inside the command line, so an attacker can inject the protocol's own delimiters (spaces and `\r\n`) to alter the command Redis executes or to smuggle additional commands onto the same connection (CWE-77 / Redis protocol injection).

## Source

- `AnnotationsController.AddAnnotation(string documentId, [FromForm] string noteText)` (`AnnotationsController.cs:18`) accepts `documentId` from the route and `noteText` from an untrusted form field, then calls `_service.SaveAnnotation(documentId, noteText)` (`AnnotationsController.cs:25`) with no validation on either value.
- `AnnotationService.SaveAnnotation` (`AnnotationService.cs:15`) copies both values verbatim into an `AnnotationRecord` (`DocumentId`, `Text`) and passes the record to `_cacheClient.StoreAnnotation(record)` (`AnnotationService.cs:24`).
- `AnnotationCacheClient.StoreAnnotation` (`AnnotationCacheClient.cs:13`) builds `key = "annotation:" + record.DocumentId` and `value = record.SavedAtUtc.ToString("O") + "|" + record.Text`, then calls `_wireWriter.SendSetCommand(key, value)` (`AnnotationCacheClient.cs:18`).
- `RedisWireWriter.SendSetCommand(string key, string value)` (`RedisWireWriter.cs:17-19`) forms `command = "SET " + key + " " + value + "\r\n"` and writes it straight to the socket (`RedisWireWriter.cs:24`) — the sink. Because `value` (and `key`) can contain the literal bytes `\r\n` or spaces, an attacker-supplied `noteText` such as `x\r\nFLUSHALL\r\nSET pwn 1` is interpreted by Redis as a second, independent command appended to the stream, and a `documentId`/`noteText` containing a space alters the argument boundaries of the `SET` call itself.

## Fix

Replace the hand-built inline-protocol string in `RedisWireWriter.SendSetCommand` with the RESP multi-bulk format, which frames every argument by an explicit byte length rather than by whitespace or CRLF delimiters. With length-prefixed framing, any bytes the caller supplies — including `\r\n` or spaces — are inert payload data and can never be parsed as a command boundary, so this closes the injection at the sink regardless of what upstream callers pass in.

```csharp
using System;
using System.Net.Sockets;
using System.Text;

namespace MultiFileRedisCommandRelay
{
    // Writes commands directly to a Redis instance using the RESP (REdis Serialization
    // Protocol) multi-bulk wire format, so argument boundaries are determined by
    // explicit byte lengths rather than by delimiter characters that caller-supplied
    // data could otherwise inject.
    public class RedisWireWriter
    {
        private readonly TcpClient _client;

        public RedisWireWriter(TcpClient client)
        {
            _client = client;
        }

        public void SendSetCommand(string key, string value)
        {
            byte[] payload = EncodeRespCommand("SET", key, value);

            NetworkStream stream = _client.GetStream();
            stream.Write(payload, 0, payload.Length);
        }

        private static byte[] EncodeRespCommand(params string[] args)
        {
            var builder = new StringBuilder();
            builder.Append('*').Append(args.Length).Append("\r\n");

            foreach (string arg in args)
            {
                byte[] argBytes = Encoding.UTF8.GetBytes(arg ?? string.Empty);
                builder.Append('$').Append(argBytes.Length).Append("\r\n");
                builder.Append(arg ?? string.Empty).Append("\r\n");
            }

            return Encoding.UTF8.GetBytes(builder.ToString());
        }
    }
}
```

Each argument (`SET`, the key, the value) is preceded by `$<byte-length>\r\n`, so Redis reads exactly that many bytes as the argument's content no matter what characters they contain, then expects the trailing `\r\n` delimiter that closes the bulk string — an embedded `\r\n` inside `value` no longer terminates anything early because Redis is counting bytes, not scanning for the delimiter.

As defense in depth, also constrain `documentId` in `AnnotationsController.AddAnnotation` to an expected shape (for example, an allowlist pattern such as alphanumeric/hyphen) before it becomes part of the cache key, since it currently reaches the sink with no validation at all.

If ongoing maintenance of a hand-rolled RESP encoder is undesirable, prefer replacing `RedisWireWriter` with the `StackExchange.Redis` client's `IDatabase.StringSet(key, value)` — the file's own comment notes this code deliberately bypasses that library's RESP framing, and restoring it removes the need to hand-maintain wire-protocol encoding at all.

## Explanation

The root cause is protocol injection, not missing output encoding in the usual sense: `SendSetCommand` uses the Redis *inline command* protocol, where argument boundaries are determined by literal space and `\r\n` characters inside the string being sent. Because `noteText` (and `documentId`) reach that string unfiltered, any `\r\n` sequence in user input is indistinguishable from a real command terminator, letting an attacker terminate the intended `SET` early and append arbitrary further Redis commands (`FLUSHALL`, `CONFIG SET`, `EVAL`, etc.) on the same connection — the Redis-protocol analogue of SQL or OS command injection. Switching to RESP's length-prefixed bulk-string framing removes the ambiguity structurally: the receiving parser never looks for a delimiter inside argument data, so no input value, regardless of content, can be interpreted as part of the command structure. Encoding or blacklisting `\r\n` in `noteText` alone would be fragile and would still leave the inline-protocol format itself parsing on whitespace; switching the wire format is the fix that addresses the sink rather than the individual caller.
