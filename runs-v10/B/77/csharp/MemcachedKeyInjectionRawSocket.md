## Verdict

exploitable

## Source

Parameter `cacheKey` in `StoreProfileSnapshot(string cacheKey, string profileJson)` originates from an upstream request header identifying the profile being refreshed. The parameter is directly concatenated into a raw Memcached protocol command string without validation, allowing injection of additional protocol commands via embedded CRLF or space characters.

## Fix

**Vulnerable Code (line 21-26):**
```csharp
public void StoreProfileSnapshot(string cacheKey, string profileJson)
{
    byte[] value = Encoding.ASCII.GetBytes(profileJson);
    string command = "set " + cacheKey + " 0 0 " + value.Length +
        "\r\n" + profileJson + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    _memcachedSocket.Send(payload);
}
```

**Fixed Code:**
```csharp
using Enyim.Caching;

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
```

## Explanation

The vulnerability stems from hand-building a Memcached inline protocol command by concatenating untrusted input. The Memcached text protocol uses spaces and CRLF as delimiters; a cache key containing either character allows an attacker to inject additional commands. For example, a key like `key\r\nget admin\r\n` would cause the server to parse two commands instead of one. The fix replaces the raw socket code with EnyimMemcachedCore's `IMemcachedClient` interface, which encodes keys and values using the binary RESP protocol and performs automatic validation that rejects control characters (bytes 0x00-0x20) in cache keys. This applies the CWE-77 remediation guidance for C#: use a maintained client library with parameterized or structured command methods rather than building protocol commands via string concatenation.

## Behaviour changes

- Constructor signature changes from `ProfileCacheWriter(Socket memcachedSocket)` to `ProfileCacheWriter(IMemcachedClient memcachedClient)`. Callers instantiating this class must provide an `IMemcachedClient` instance instead of a raw socket. This is a breaking API change, but is necessary to use the recommended safe pattern.
- The `Store()` call on line 1 (new code) returns a boolean indicating whether the operation succeeded. The original `Send()` call does not return a value. Callers should check this result or use an overload that throws on failure.
- The method no longer constructs or sends raw protocol bytes; all serialization is handled by the client library.
- EnyimMemcachedCore must be added as a NuGet dependency if not already present.
