## Verdict

Confirmed. `cacheKey` is attacker-influenced (derived from an upstream request header) and is concatenated directly into the memcached text-protocol `set` command written to the raw socket. Memcached's line-oriented ASCII protocol splits the command on whitespace and terminates it on `\r\n`, so a key containing a space or a CRLF sequence lets an attacker close the intended `set` command early and inject additional memcached protocol commands (or corrupt the declared data length framing) over the same connection. This is command injection into the memcached protocol interpreter (CWE-77).

## Source

`cacheKey` parameter of `ProfileCacheWriter.StoreProfileSnapshot`, documented as originating from an upstream request header (`"profile:" + tenantSlug`), flowing unmodified into the `command` string built at line 21 and sent raw to the socket at line 26.

## Fix

### File: MemcachedKeyInjectionRawSocket.cs
```csharp
using System;
using System.Net.Sockets;
using System.Text;

namespace CacheGateway
{
    public class ProfileCacheWriter
    {
        private readonly Socket _memcachedSocket;

        public ProfileCacheWriter(Socket memcachedSocket)
        {
            _memcachedSocket = memcachedSocket;
        }

        // cacheKey originates from an upstream request header identifying the
        // profile being refreshed, e.g. "profile:" + tenantSlug.
        public void StoreProfileSnapshot(string cacheKey, string profileJson)
        {
            ValidateCacheKey(cacheKey);

            byte[] value = Encoding.ASCII.GetBytes(profileJson);
            string command = "set " + cacheKey + " 0 0 " + value.Length +
                "\r\n" + profileJson + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            _memcachedSocket.Send(payload);
        }

        // The memcached text protocol delimits the "set" command on
        // whitespace and terminates it on CR/LF, so any of those characters
        // embedded in the key let an attacker close the command early and
        // smuggle additional memcached commands (or corrupt the data-length
        // framing) down the same connection. Reject rather than strip:
        // stripping would silently rewrite the key into a different, valid
        // cache entry instead of surfacing the bad input.
        private static void ValidateCacheKey(string cacheKey)
        {
            if (string.IsNullOrEmpty(cacheKey))
            {
                throw new ArgumentException("Cache key must not be empty.", nameof(cacheKey));
            }

            if (cacheKey.Length > 250)
            {
                throw new ArgumentException(
                    "Cache key exceeds the 250-byte memcached key limit.", nameof(cacheKey));
            }

            foreach (char c in cacheKey)
            {
                if (c <= 0x20 || c == 0x7F)
                {
                    throw new ArgumentException(
                        "Cache key contains a whitespace or control character, which the memcached protocol does not permit in a key.",
                        nameof(cacheKey));
                }
            }
        }
    }
}
```

## Explanation

The memcached `set` command is a single ASCII line: `set <key> <flags> <exptime> <bytes>\r\n<data>\r\n`. The protocol has no escaping mechanism for the key field, so the only sound defense is to reject any key that cannot appear literally in that line. `ValidateCacheKey` enforces the two constraints memcached itself imposes on keys: no whitespace or control characters (`<= 0x20` covers space, tab, CR, LF; `0x7F` covers DEL) and a maximum length of 250 bytes. Rejecting the key with an exception (rather than stripping or encoding the offending characters) avoids silently redirecting the write to a different, attacker-chosen cache entry, and surfaces the malformed input to the caller so it can be traced back to the upstream header that produced it. The rest of the command-construction and socket-write logic is unchanged.
