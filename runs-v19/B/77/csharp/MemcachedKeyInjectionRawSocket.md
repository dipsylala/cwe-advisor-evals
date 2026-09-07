## Verdict

Real vulnerability confirmed. The code concatenates untrusted `cacheKey` into a Memcached inline-protocol command string, then sends it over a raw socket. The inline protocol is space and CRLF delimited, so an attacker controlling the header can inject additional commands.

## Source

Line 21-22 of MemcachedKeyInjectionRawSocket.cs: `cacheKey` is concatenated into the command string without sanitization.

Line 26: The untrusted payload is sent directly via `Socket.Send()`.

## Fix

Replace the raw socket manipulation with `EnyimMemcachedCore`'s typed `IMemcachedClient` API:

### File: MemcachedKeyInjectionRawSocket.cs

```csharp
using System;
using Enyim.Caching;
using Enyim.Caching.Memcached;

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
            // Use the typed Store method instead of building the command string.
            // The client library's binary protocol includes explicit length prefixes,
            // so embedded delimiters cannot split into new commands.
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation

The fix replaces the vulnerable raw-socket code with `EnyimMemcachedCore`'s `IMemcachedClient.Store()` typed method. 

**What changed:**
- The constructor now accepts an `IMemcachedClient` instead of a raw `Socket`
- `StoreMode.Set` replaces the manual `set` command construction
- The key and value are passed as separate arguments to the `Store()` method, not concatenated into a command string
- The underlying binary protocol used by the client library encodes each argument with an explicit byte-length prefix, so embedded CRLF, spaces, or other delimiters in the key are transmitted as literal data and cannot form new commands

**Why it eliminates the weakness:**
The Memcached binary protocol (RESP-like) prefixes each argument with its length, preventing delimiter injection. An attacker-supplied key like `"profile:\r\nset injected"` is transmitted as a single key argument with length 27, not parsed as two commands. The client library handles the framing automatically, eliminating the string-concatenation vulnerability.

**Preserved behaviour:**
The `Store()` method with `StoreMode.Set` replaces the `set` command with zero expiration and zero flags, preserving the original semantics. The value is stored without modification.

## Behaviour changes

- **Explicit dependency:** The code now requires the `Enyim.Caching` NuGet package (EnyimMemcachedCore). The exact version should be confirmed against your dependency-check/SCA tooling.
- **Client initialization:** The constructor now takes an `IMemcachedClient` instance, which must be constructed and passed at instantiation time rather than a raw socket.
- **Exception model:** Store failures now raise `MemcachedClientException` or related exception types from the Enyim library instead of `SocketException`.
- **Timeout/reliability:** The typed client includes built-in connection pooling, retry logic, and timeout handling, making the code more robust than raw socket manipulation.
