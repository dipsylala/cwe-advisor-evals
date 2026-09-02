## Verdict

Exploitable. Confidence: high.

`StoreProfileSnapshot` builds a Memcached text-protocol `set` command by concatenating an untrusted key directly into a space-delimited, CRLF-terminated command line, then writes it to a raw `Socket`. The Memcached inline protocol has no framing on the key/command-line portion (only the data block is length-delimited), so a key containing a space or `\r\n` lets an attacker terminate the intended command early and splice in arbitrary follow-on Memcached commands (e.g. inject an extra `set`/`delete`/`flush_all` line) on the same connection.

## Source

`cacheKey`, the first parameter of `StoreProfileSnapshot(string cacheKey, string profileJson)`. Per the method's own comment, it originates from an upstream request header identifying the profile being refreshed (e.g. `"profile:" + tenantSlug`), making it attacker-influenceable request data with no validation applied before use.

Sink: `_memcachedSocket.Send(payload)` at line 26, where `payload` is the ASCII-encoded bytes of `command`, built at lines 21-22 as `"set " + cacheKey + " 0 0 " + value.Length + "\r\n" + profileJson + "\r\n"`.

## Fix

**Library recommendation:** EnyimMemcachedCore (`Enyim.Caching` / `EnyimMemcachedCore` NuGet package), the maintained .NET Memcached client. The knowledge base does not supply a minimum safe version for this library - confirm the resolved package version against SCA/dependency-check tooling before merging. EnyimMemcachedCore's default `DefaultKeyTransformer` rejects keys containing bytes `0x00`-`0x20` (including space and CRLF) with an `ArgumentException`, which is what closes this finding - safety here comes from the client refusing the dangerous byte, not from any framing on the key.

Vulnerable code:

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
            byte[] value = Encoding.ASCII.GetBytes(profileJson);
            string command = "set " + cacheKey + " 0 0 " + value.Length +
                "\r\n" + profileJson + "\r\n";
            byte[] payload = Encoding.ASCII.GetBytes(command);

            // VULNERABLE: cacheKey is concatenated directly into a
            // space-delimited, CRLF-terminated command line with no
            // neutralization of space/CRLF bytes.
            _memcachedSocket.Send(payload);
        }
    }
}
```

Fixed code:

```csharp
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
            // EnyimMemcachedCore's DefaultKeyTransformer throws
            // ArgumentException for any key byte in 0x00-0x20 (space, CRLF,
            // etc.), so cacheKey can no longer break out of the key position
            // and inject a second command onto the wire.
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation

The fix replaces the hand-built Memcached inline-protocol command and raw `Socket.Send` with EnyimMemcachedCore's typed `IMemcachedClient.Store` call, so the untrusted `cacheKey` is passed as a discrete key argument rather than folded into a manually assembled command string. The client's `DefaultKeyTransformer` validates every key before it is placed on the wire and rejects the delimiter/terminator bytes (space, CRLF, and other control characters) that made the injection possible, so `cacheKey` can no longer terminate the `set` line early or introduce a second command. This is a library-level fix, not a version bump - the knowledge base carries no CVE or minimum version for this library, so no such claim is made; the developer should still confirm the resolved package version through SCA tooling.

## Behaviour changes

- Constructor signature changed from `Socket` to `IMemcachedClient`: the class no longer owns/uses a raw socket, so the caller must be updated to construct/inject an `IMemcachedClient` (typically registered once via EnyimMemcachedCore's DI setup) instead of a `Socket`. This is required by the fix - there is no parameterized way to keep using a raw `Socket` for the Memcached protocol.
- Manual ASCII encoding and command-string assembly (`Encoding.ASCII.GetBytes`, the `value.Length` byte count, and the `"set " + ... + "\r\n"` framing) are removed; the client library serializes the key/value and frames the request internally. This is a mechanism change only - the resulting stored value is the same `profileJson` string.
- Explicit `flags` and `exptime` (`0 0` in the original command) are no longer passed. `IMemcachedClient.Store(StoreMode.Set, key, value)` without an expiration argument stores with no expiration, matching the original `exptime=0` ("never expire") semantics; flags are handled by the client's default transcoder rather than the caller, which was already effectively unused (always `0`) in the original code.
- A key containing bytes `0x00`-`0x20` now throws `ArgumentException` from the client instead of being silently sent as (potentially multiple) Memcached commands. Call sites that pass such a key will now fail fast; this is the intended effect of the fix and should be handled (e.g. caught and logged, or the key validated/normalized before this call) rather than allowed to propagate as an unhandled exception.

Assumptions: `cacheKey` is treated as attacker-influenceable per the method's own source comment, since no SAST-provided call path into `StoreProfileSnapshot` was supplied beyond that comment. EnyimMemcachedCore was selected as the concrete replacement library because it is the one the C# CWE-77 guidance names explicitly for this exact Memcached-over-raw-socket scenario; no alternative maintained Memcached client was considered.
