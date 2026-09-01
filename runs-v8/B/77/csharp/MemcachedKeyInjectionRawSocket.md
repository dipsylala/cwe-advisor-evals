## Verdict

Confirmed. The `cacheKey` parameter originates from an untrusted upstream request header and is concatenated directly into a memcached wire-protocol command string sent over a raw socket. The memcached text protocol is space-delimited and CRLF-terminated; an attacker can inject delimiters into the key to split the command and inject additional memcached operations.

## Source

`cacheKey` parameter in `StoreProfileSnapshot()` method, originating from an upstream request header identifying the profile being refreshed.

## Fix

**Recommended approach:** Replace raw socket communication with EnyimMemcachedCore, a maintained .NET Memcached client library that handles protocol framing and validates keys:

```csharp
using System;
using Enyim.Caching;
using Enyim.Caching.Configuration;

namespace CacheGateway
{
    public class ProfileCacheWriter
    {
        private readonly IMemcachedClient _memcachedClient;

        public ProfileCacheWriter(IMemcachedClient memcachedClient)
        {
            _memcachedClient = memcachedClient;
        }

        public void StoreProfileSnapshot(string cacheKey, string profileJson)
        {
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

**Alternative (if raw socket must remain):** Validate `cacheKey` against an allowlist before concatenating:

```csharp
public void StoreProfileSnapshot(string cacheKey, string profileJson)
{
    // Validate cacheKey: only alphanumeric, hyphens, colons, and underscores
    if (!System.Text.RegularExpressions.Regex.IsMatch(cacheKey, @"^[a-zA-Z0-9:_-]+\z"))
    {
        throw new ArgumentException("Invalid cache key format", nameof(cacheKey));
    }

    byte[] value = Encoding.ASCII.GetBytes(profileJson);
    string command = "set " + cacheKey + " 0 0 " + value.Length +
        "\r\n" + profileJson + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    _memcachedSocket.Send(payload);
}
```

## Explanation

The vulnerability occurs because untrusted input (`cacheKey`) is concatenated directly into a memcached wire-protocol command string. The memcached text protocol uses spaces to delimit command tokens and CRLF (`\r\n`) to terminate commands. An attacker can embed these delimiters in the key to split the current command and inject new commands—for example, a key like `profile\r\ndel victim-key\r\n` would execute an additional `del` command.

The first fix (recommended) uses EnyimMemcachedCore, which encodes keys and values with length-prefixed format that prevents delimiter interpretation. The library's default `DefaultKeyTransformer` also validates keys, rejecting bytes 0x00–0x20 (including space) that could cause protocol injection.

The second fix (if raw socket usage is unavoidable) applies allowlisting to reject keys containing or resembling protocol delimiters, limiting the key format to safe characters. The regex uses `\z` (absolute string end) rather than `$` to account for .NET regex behavior where `$` matches before a trailing newline.

## Behaviour changes

**With EnyimMemcachedCore:**
- Method signature changes from socket-based to using an `IMemcachedClient` injected into the constructor
- Return type remains void; exception handling remains unchanged (the client library throws on operation failure)
- Caller responsibility changes: instead of managing a raw socket connection, the application configures the memcached client library once at startup

**With allowlist validation:**
- Rejects cache keys that do not conform to the safe character set (raises `ArgumentException`)
- Legitimate keys must use only alphanumeric characters, colons, hyphens, and underscores
- All other behaviour remains identical if the key passes validation
