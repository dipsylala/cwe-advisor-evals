## Verdict

Confirmed command injection vulnerability. The `cacheKey` parameter is concatenated directly into a Memcached protocol command without validation, allowing an attacker to inject additional commands or modify the intended operation by embedding protocol delimiters (spaces, newlines, carriage returns).

## Source

`cacheKey` originates from a request header (line 16-17 comment) and flows directly into the command string construction at lines 21-22. An attacker can supply a value containing `\r\n` to inject a second command, or spaces to redefine the key itself and inject additional operands.

## Fix

### File: MemcachedKeyInjectionRawSocket.cs

```csharp
using System;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

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
            // Validate cacheKey: Memcached keys must not contain whitespace or control characters
            // and must be at most 250 bytes per the Memcached protocol
            if (string.IsNullOrEmpty(cacheKey) || cacheKey.Length > 250 || 
                !Regex.IsMatch(cacheKey, @"^[\x21-\x7E]+$"))
            {
                throw new ArgumentException("Invalid cache key: must contain only printable ASCII characters (excluding whitespace), and be at most 250 bytes.", nameof(cacheKey));
            }

            byte[] value = Encoding.ASCII.GetBytes(profileJson);
            string command = "set " + cacheKey + " 0 0 " + value.Length +
                "\r\n" + profileJson + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            _memcachedSocket.Send(payload);
        }
    }
}
```

## Explanation

The fix adds strict validation of the `cacheKey` before it is used in command construction. The validation enforces:

1. **Non-empty and length-bounded**: Rejects null, empty, or keys exceeding 250 bytes (Memcached protocol limit).
2. **Printable ASCII only**: The regex pattern `^[\x21-\x7E]+$` allows only printable ASCII characters (0x21–0x7E), which excludes whitespace, newlines, carriage returns, and control characters that could break out of the command syntax.
3. **Early rejection**: Validation occurs before the key is used, preventing injection at the command construction point.

Memcached command structure uses spaces to delimit operands and `\r\n` to terminate commands. By restricting `cacheKey` to printable non-whitespace characters, the attacker cannot inject additional protocol elements, closing the injection vector.
