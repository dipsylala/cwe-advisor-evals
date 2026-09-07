## Verdict

Exploitable.

## Source

`cacheKey` parameter in `StoreProfileSnapshot()` method (line 18), documented as originating from an upstream request header and constructed as `"profile:" + tenantSlug`. The `tenantSlug` portion is attacker-controlled.

## Fix

**Vulnerable code:**
```csharp
public void StoreProfileSnapshot(string cacheKey, string profileJson)
{
    byte[] value = Encoding.ASCII.GetBytes(profileJson);
    string command = "set " + cacheKey + " 0 0 " + value.Length +
        "\r\n" + profileJson + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    // SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
    _memcachedSocket.Send(payload);
}
```

**Fixed code:**
```csharp
public void StoreProfileSnapshot(string cacheKey, string profileJson)
{
    // Use the client library's parameterized API, which validates the key
    // and encodes each argument with explicit length prefixing in RESP protocol,
    // preventing delimiter injection.
    _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
}
```

**Constructor change:**
Replace:
```csharp
private readonly Socket _memcachedSocket;

public ProfileCacheWriter(Socket memcachedSocket)
{
    _memcachedSocket = memcachedSocket;
}
```

With:
```csharp
private readonly IMemcachedClient _memcachedClient;

public ProfileCacheWriter(IMemcachedClient memcachedClient)
{
    _memcachedClient = memcachedClient;
}
```

**Import statement:**
```csharp
using Enyim.Caching;
```

## Explanation

The original code hand-builds a Memcached inline protocol command string by concatenating the untrusted `cacheKey` directly into the command, then sends it over a raw socket. The Memcached inline protocol uses space and CRLF as delimiters; an attacker can inject spaces to split arguments or CRLF sequences to inject arbitrary commands (for example, `profile:value\r\nflush_all\r\n` would execute `flush_all` after storing the key). The fix replaces the raw socket and string concatenation with EnyimMemcachedCore's `IMemcachedClient.Store()` API, which provides parameterized command construction. The client library's `DefaultKeyTransformer` validates keys by rejecting bytes in the 0x00–0x20 range (including space and control characters like CRLF), and the underlying RESP protocol encodes each argument with an explicit length prefix, so embedded delimiters in the value cannot be misinterpreted as command separators.

## Behaviour changes

1. **Constructor injection:** `Socket` replaced with `IMemcachedClient`. This is a breaking change for callers but is necessary to use the safe API. The dependency injection pattern is standard in .NET and supports proper initialization of the client with connection pooling and retry logic.

2. **Return value:** `Socket.Send()` returns `int` (bytes sent), which the original code discarded. `IMemcachedClient.Store()` returns `bool` indicating success or failure. Callers should check this return value or wrap the call in a try-catch to handle `MemcachedClientException` on connection or protocol errors.

3. **Exception handling:** `SocketException` is replaced by exceptions from the client library (primarily `MemcachedClientException` and `InvalidOperationException`). The client library provides more specific failure modes (connection lost, timeout, key validation failure).

4. **Key validation:** The client library's `DefaultKeyTransformer` now validates `cacheKey` and throws `ArgumentException` if it contains bytes in 0x00–0x20 (spaces, control characters, CRLF), or if it exceeds the protocol's maximum key length. This validation is automatic and cannot be bypassed, closing the injection vector.

5. **Encoding:** The original code explicitly encoded to ASCII. The client library handles encoding internally and uses the appropriate format for the RESP protocol; no manual encoding is needed.
