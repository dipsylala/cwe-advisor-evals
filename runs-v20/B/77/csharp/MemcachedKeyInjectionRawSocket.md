## Verdict

- **CWE-77** (Improper Neutralization of Special Elements used in a Command, non-shell command interpreter case) - **exploitable**
- Location: `MemcachedKeyInjectionRawSocket.cs`, `ProfileCacheWriter.StoreProfileSnapshot`, sink at line 26 (`_memcachedSocket.Send(payload)`)
- Confidence: high

## Source

`cacheKey`, the first parameter of `StoreProfileSnapshot`. Per the method's own comment it originates from an upstream request header identifying the profile being refreshed (e.g. `"profile:" + tenantSlug`), so it is attacker-influenced and reaches the method with no validation applied anywhere in the file.

## Fix

The memcached inline (text) protocol places the key on a space-delimited, CRLF-terminated command line; only the data block that follows is length-delimited. Building `"set " + cacheKey + " 0 0 " + value.Length + "\r\n" + profileJson + "\r\n"` by concatenation lets a `cacheKey` containing a space or `\r\n` terminate the `set` command early and inject additional memcached command lines (e.g. a second `set` targeting a different key, or a `delete`/`flush_all`) that the server will execute as if they came from the application. `profileJson` is not part of the vulnerable pattern: it lands after an explicit byte-length prefix, so embedded delimiters in it cannot extend the command line.

Per the loaded C# guidance for this CWE, raw-socket inline-protocol commands over `Socket`/`NetworkStream` should be replaced with a maintained client library's structured API rather than hand-built strings. For memcached specifically, the guidance names EnyimMemcachedCore's `IMemcachedClient`/`MemcachedClient` (namespace `Enyim.Caching`) with `StoreMode` in `Enyim.Caching.Memcached`, whose default key transformer (`DefaultKeyTransformer`) rejects control characters and spaces (0x00-0x20) in a key by throwing `ArgumentException`, closing the injection at the client layer instead of relying on hand-rolled escaping. The guidance gives no minimum-safe-version for this package (there is no CVE driving this fix); resolve the version through your own SCA/dependency-check tooling rather than pinning to the one used here for verification.

### File: MemcachedKeyInjectionRawSocket.cs
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
            _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
        }
    }
}
```

## Explanation

The raw-socket, hand-built `"set " + cacheKey + " ..."` command line is replaced with `IMemcachedClient.Store(StoreMode.Set, cacheKey, profileJson)`. `IMemcachedClient` frames the memcached protocol itself instead of building a command string by concatenation, and its default key transformer validates `cacheKey` before any bytes reach the wire, throwing `ArgumentException` for a key containing a space or a control character (0x00-0x20) rather than sending it as literal command-line text. This removes the untrusted value from the position where it could terminate or extend the `set` command, which is what eliminates the injection; no allowlist or escaping of `cacheKey` is needed in application code because the client's key transformer already enforces that constraint on every call.

## Behaviour changes

- **Constructor dependency changed**: `ProfileCacheWriter` now takes an `IMemcachedClient` instead of a connected `Socket`. This is required by the fix - there is no way to reach the client's parameterized `Store` API while keeping a raw `Socket` as the dependency - but it means the caller must be updated to inject a configured `IMemcachedClient` (typically registered via DI, e.g. `services.AddEnyimMemcached(...)`) instead of constructing/passing a `Socket`. This propagates to every call site that constructs `ProfileCacheWriter`, none of which are in this file.
- **New failure mode for previously "successful" malicious input**: a `cacheKey` containing a space or control character, which previously succeeded in silently injecting a second command, now throws `ArgumentException` synchronously from `Store`. This is the intended effect of the fix, not a regression, but callers that pass such a key must now handle the exception (or, better, fix the upstream header parsing so a well-formed key never contains one).
- **Return value discarded either way, but the type differs**: the original discarded `Socket.Send`'s `int` (bytes sent - so a partial send was silently undetected); the fix discards `Store`'s `bool` success result in the same fire-and-forget style. No new success/failure signal is surfaced to the caller in either version, so caller-visible behaviour is unchanged here, though `Store`'s `bool` is available if the caller later wants to check it.
- **Value framing/serialization is now the client's responsibility**: the original built an explicit ASCII length-prefixed data block (`value.Length`) for `profileJson`; the fix passes `profileJson` as the `Store` value and lets EnyimMemcachedCore's transcoder frame and serialize it. This is a necessary consequence of using the client API (the guidance's fix is not "keep the hand-built command line, just fix the key") and was not itself part of the vulnerable pattern, since `profileJson` was already safely length-delimited before. Confirm against the memcached values already stored under this key (if any existing entries were written by the old raw-socket path) that downstream readers deserializing the value are compatible with the client's on-wire encoding of a `string`.
- **Removed unused imports**: `System.Net.Sockets` and `System.Text` are no longer referenced and were removed; no other file content changed.
- Everything else - method name, parameter names/order, the field being `readonly`, the namespace, the descriptive comment above `StoreProfileSnapshot` - is unchanged.

**Verification**: the fixed file was compiled with `dotnet build` (.NET SDK 10.0.203) in a scratch class library referencing the real `EnyimMemcachedCore` NuGet package (v3.5.1, the latest on nuget.org at the time of this fix) - not a stub - to confirm `IMemcachedClient`, `Enyim.Caching`, `Enyim.Caching.Memcached.StoreMode`, and the `Store(StoreMode, string, object)` overload all exist and resolve as used. Build succeeded with 0 errors (unrelated transitive `MessagePack` NU1902/NU1903 advisory warnings only, from EnyimMemcachedCore's own dependency tree, not from this fix). Every name the fix introduces beyond the original file (`IMemcachedClient`, `Store`, `StoreMode`, `Enyim.Caching`, `Enyim.Caching.Memcached`) is named explicitly in the loaded `cwe/77/csharp/INDEX.md` guidance or was confirmed by this compile.

**Assumptions**: none needed for CWE/language identification - the finding's CWE-77 label, the file extension, and the raw-socket memcached pattern matched the loaded guidance directly (memcached routes to CWE-77's C# guidance rather than CWE-78, since the sink is a cache protocol interpreter, not an OS shell). The exact `Store` overload resolution (binding `profileJson` to the `object value` parameter) was confirmed by the compile above rather than assumed.
