## Verdict
Confirmed real vulnerability. Untrusted input (cacheKey from request headers) is concatenated into a raw Memcached inline-protocol command string without sanitization, enabling CRLF injection to execute arbitrary Memcached commands.

## Source
**Vulnerable Sink**: Line 26 - `_memcachedSocket.Send(payload);`

**Data Flow:**
- Request header → `cacheKey` parameter (line 18)
- String concatenation (lines 21–22): `"set " + cacheKey + " 0 0 " + value.Length + "\r\n" + profileJson + "\r\n"`
- Malicious cacheKey like `"key\r\nflush_all\r\n"` results in two Memcached commands: `set key` and `flush_all`
- Payload sent over raw Socket (line 26)

## Fix

### File: MemcachedKeyInjectionRawSocket.cs

```csharp
using System;
using EnyimMemcached;

namespace CacheGateway
{
    public class ProfileCacheWriter
    {
        private readonly IMemcachedClient _memcachedClient;

        public ProfileCacheWriter(IMemcachedClient memcachedClient)
        {
            _memcachedClient = memcachedClient;
        }

        // cacheKey originates from an upstream request header identifying the
        // profile being refreshed, e.g. "profile:" + tenantSlug.
        public void StoreProfileSnapshot(string cacheKey, string profileJson)
        {
            // Use the client library's parameterized API instead of hand-building
            // the raw Memcached command string. IMemcachedClient.Store() validates
            // the key and properly frames it in the protocol, preventing CRLF injection.
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation
The fix replaces hand-built raw Memcached protocol commands with EnyimMemcachedCore's typed `Store()` API. This eliminates CWE-77 by:

1. **Key Validation**: EnyimMemcachedCore's `DefaultKeyTransformer` rejects keys containing bytes 0x00–0x20 (including CR, LF, tab, and space), throwing `ArgumentException` before the key reaches the wire. Embedded newlines cannot become command boundaries.

2. **Proper Protocol Framing**: The `Store()` method encodes each argument (key and value) with length prefixes and delimiters in the Memcached protocol, ensuring embedded delimiters are treated as literal data, not command syntax.

3. **Separation of Input and Command**: The key and value arrive as separate method parameters, not concatenated into one command string, so metacharacters in the value cannot cross into the key position.

The original behavior is preserved: setting a key with no expiration (the `StoreMode.Set` default).

## Behaviour changes
- **Constructor**: Now accepts `IMemcachedClient` instead of `Socket`; dependency injection pattern replaces raw socket management.
- **Implementation**: Calls parameterized `Store()` instead of building and sending raw protocol bytes; encoding/framing handled by client library.
- **Key Validation**: Keys containing control characters or spaces now raise `ArgumentException` at the call site (client-side) rather than potentially being transmitted.
- **Dependencies**: Requires NuGet package `EnyimMemcachedCore` (specific version should be verified against SCA/dependency-check; latest maintained versions enforce key validation).
