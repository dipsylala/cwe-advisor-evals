## Verdict

Exploitable

## Source

`cacheKey` parameter passed to `StoreProfileSnapshot()` method. The method documentation states it originates from an upstream request header and is attacker-controlled.

## Fix

**Vulnerable code:**
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

        public void StoreProfileSnapshot(string cacheKey, string profileJson)
        {
            byte[] value = Encoding.ASCII.GetBytes(profileJson);
            string command = "set " + cacheKey + " 0 0 " + value.Length +
                "\r\n" + profileJson + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            // VULNERABILITY: cacheKey injected directly into protocol command string
            _memcachedSocket.Send(payload);
        }
    }
}
```

**Fixed code:**
```csharp
using System;
using Enyim.Caching;

namespace CacheGateway
{
    public class ProfileCacheWriter
    {
        private readonly MemcachedClient _memcachedClient;

        public ProfileCacheWriter(MemcachedClient memcachedClient)
        {
            _memcachedClient = memcachedClient;
        }

        public void StoreProfileSnapshot(string cacheKey, string profileJson)
        {
            // Safe: client library validates key and prevents injection via DefaultKeyTransformer
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation

The vulnerability arises from manually building a Memcached inline protocol command string via concatenation of untrusted input. A `cacheKey` containing CRLF (`\r\n`) or other protocol delimiters can split the command into multiple commands executed by the server. For example, a key like `profile:\r\ndelete admin\r\n` would cause the Memcached server to interpret the message as two separate commands rather than one.

The fix replaces raw socket communication and manual protocol building with the EnyimMemcachedCore client library. This library's `Store()` method and `DefaultKeyTransformer` validate keys by rejecting bytes 0x00-0x20 (including CRLF, space, and tab), preventing an attacker from injecting protocol delimiters. The library also properly encodes the value using the binary-safe Memcached protocol, eliminating the need to build command strings by hand.

## Behaviour changes

- **Dependency added:** Enyim.Caching (EnyimMemcachedCore). Version selection should be verified against current SCA/dependency-check tooling; the library is actively maintained.
- **Constructor parameter changed:** From `Socket _memcachedSocket` to `MemcachedClient _memcachedClient`. The calling code must construct and inject a `MemcachedClient` instead of a raw socket.
- **Key validation:** The `DefaultKeyTransformer` automatically validates `cacheKey` and throws `ArgumentException` if it contains 0x00-0x20 bytes. Any existing callers passing keys with these bytes will now fail immediately at the call site rather than silently injecting commands.
- **Automatic expiration handling:** The fixed code uses `StoreMode.Set` with the client library's default behavior. The original code manually set expiration to 0 (no expiration) with `"0 0"` flags in the protocol. The client library respects the default `TimeSpan` for expiration policy; verify this matches your application's caching requirements and adjust via the `IMemcachedClient.Store()` overload with an explicit `expiration` parameter if needed.
- **Removed manual encoding:** The original code manually created byte arrays; the client library handles encoding transparently.
