## Verdict
exploitable

## Source
`cacheKey` parameter in `StoreProfileSnapshot` method (untrusted input from upstream request header identifying the profile being refreshed). Flows directly into the Memcached command string via concatenation at lines 21-22.

## Fix

### File: MemcachedKeyInjectionRawSocket.cs

```csharp
using System;
using Enyim.Caching;

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
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation
The original code hand-built a raw Memcached ASCII protocol command string by concatenating the untrusted `cacheKey` directly into the command: `"set " + cacheKey + " 0 0 " + value.Length + "\r\n" + profileJson + "\r\n"`. In the Memcached ASCII protocol, the key sits on a space-delimited, CRLF-terminated command line. An attacker controlling `cacheKey` can inject CRLF or space characters to terminate the key prematurely, causing protocol parsing errors or command injection.

The fix replaces the raw socket communication with EnyimMemcachedCore's `IMemcachedClient` interface and its typed `Store` method. EnyimMemcachedCore's default `DefaultKeyTransformer` automatically validates the key, throwing `ArgumentException` for any bytes in the range 0x00-0x20 (which includes space and control characters like CRLF). This prevents delimiter injection at the source. The client library encapsulates the Memcached protocol and uses safe framing for all argument passing.

**Library recommendation:** EnyimMemcachedCore (no specific version constraint from the knowledge base; verify the resolved version against dependency-check tooling before merging).

## Behaviour changes
The constructor signature changes from accepting `Socket memcachedSocket` to accepting `IMemcachedClient memcachedClient`. This is a breaking change to the class's dependency injection contract, but it aligns with best practices by decoupling the class from low-level socket handling. The method signature remains unchanged. Error handling changes: the original code relies on `Socket.Send()` throwing `SocketException` on network errors; the new code relies on `IMemcachedClient.Store()` throwing `MemcachedException` or related exceptions. The method now returns `bool` (success/failure) instead of implicit void, which should be captured and handled by the caller to detect cache write failures. The Memcached protocol handling is now delegated to the library, which uses RESP-like length-delimited framing instead of the hand-built ASCII format, but this is transparent to the caller.
