## Verdict

**Exploitable.** The untrusted `cacheKey` parameter (sourced from an upstream request header) is concatenated into a raw Memcached inline-protocol command string without validation. The Memcached inline protocol uses space and CRLF as command delimiters at the protocol level; an attacker-controlled key containing either character can split the command and inject additional commands. Example: `cacheKey = "profile:\r\nflushall"` produces two commands: `set profile:` (incomplete, rejected) and `flushall` (executed).

## Source

**Input:** `cacheKey` parameter, documented as originating from an upstream request header. No validation occurs before use.

**Sink:** `_memcachedSocket.Send(payload)` at line 26.

**Call chain:**
1. Line 18: `StoreProfileSnapshot(string cacheKey, string profileJson)` receives untrusted `cacheKey`
2. Line 21-22: `cacheKey` is concatenated into the command string: `"set " + cacheKey + " 0 0 " + value.Length + "\r\n" + profileJson + "\r\n"`
3. Line 23: Command string is encoded to bytes
4. Line 26: Bytes are sent to the Memcached socket via `Socket.Send(payload)`

**Why concatenation is unsafe:** Memcached's inline protocol is delimited by space and CRLF. The key sits on the space-delimited command line: `set <key> <flags> <exptime> <bytes>`. An embedded space or CRLF in `<key>` terminates that argument and begins parsing a new argument or a new command. Unlike the data block (which is length-delimited), the key is unprotected.

## Fix

The fix replaces the raw socket and hand-built command string with the EnyimMemcachedCore client library's `IMemcachedClient`, which provides a parameterized `Store()` method. The client's `DefaultKeyTransformer` validates keys and rejects control characters (0x00-0x20) and spaces, and the `Store()` method safely serializes arguments using length-prefixed encoding.

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
            // EnyimMemcachedCore's IMemcachedClient.Store() method:
            // - Validates the key via DefaultKeyTransformer, which throws ArgumentException
            //   for control characters (0x00-0x20) and spaces, preventing injection.
            // - Encodes arguments using length-prefixed serialization (not delimited by
            //   space or CRLF), so embedded delimiters are treated as literal data.
            // - StoreMode.Set corresponds to the Memcached "set" command.
            // - Timeout of zero means no expiration (same as original timeout=0, exptime=0).
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation

The original code builds a Memcached command by concatenating the untrusted `cacheKey` into an inline-protocol command string and sends it directly over a raw socket. Memcached's inline protocol delimits command arguments by space and command boundaries by CRLF; a key containing either character becomes two separate commands instead of one, allowing an attacker to inject arbitrary operations.

The fix replaces the raw socket with EnyimMemcachedCore's `IMemcachedClient`, which provides the parameterized `Store(StoreMode mode, string key, object value)` method. This method:

1. **Validates the key** via `DefaultKeyTransformer` (the default transformer), which throws `ArgumentException` if the key contains any control character (bytes 0x00–0x20) or space. This rejects CRLF (`\r\n`), LF (`\n`), CR (`\r`), space, tab, and other control bytes before they reach the wire.
2. **Encodes arguments safely** by serializing the key and value with length prefixes (Memcached binary/RESP protocol), not space-delimited strings. Embedded delimiters become literal data, not command separators.
3. **Matches the original contract** by supporting `StoreMode.Set` (equivalent to `set` command), no expiration (timeout 0), and string values (profileJson).

**Dependency:** EnyimMemcachedCore (NuGet package `EnyimMemcached` or `EnyimMemcachedCore`). The version is determined by your project's SCA/dependency check process; confirm the resolved version against security advisories.

## Behaviour changes

1. **Constructor parameter changed:** `Socket memcachedSocket` → `IMemcachedClient memcachedClient`. The caller must now provide an `IMemcachedClient` instance instead of a `Socket`. This is typically obtained from a dependency injection container or factory.

2. **Method signature preserved:** The `StoreProfileSnapshot` method signature is unchanged from the caller's perspective.

3. **Return value changed:** The original `Socket.Send()` returned the number of bytes sent (type `int`), which the original code discarded. The fixed `Store()` returns `bool` (success/failure), which is more semantically correct for a cache operation and also discarded. Both match the original code's fire-and-forget pattern.

4. **Failure behavior improved:** The original code had no error handling; a socket error would throw an exception. The fixed code also throws on network errors, but additionally throws `ArgumentException` if `cacheKey` contains control characters or spaces (from the key transformer), catching the injection attempt early and explicitly.

5. **No breaking changes to the application's logic:** The fix stores the same value with the same key semantics (zero timeout, zero flags, string serialization) as the original.
