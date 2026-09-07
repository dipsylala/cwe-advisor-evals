## Verdict

Exploitable.

## Source

`cacheKey` parameter (line 18) originates from an upstream request header. An attacker can supply a value containing `\r\n` (carriage return + line feed), which is the Memcached inline-protocol command delimiter.

## Fix

**Vulnerable code:**

```csharp
public void StoreProfileSnapshot(string cacheKey, string profileJson)
{
    byte[] value = Encoding.ASCII.GetBytes(profileJson);
    string command = "set " + cacheKey + " 0 0 " + value.Length +
        "\r\n" + profileJson + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    // Sink: untrusted cacheKey is embedded in the command string
    _memcachedSocket.Send(payload);
}
```

**Fixed code:**

```csharp
using EnyimMemcached;

public class ProfileCacheWriter
{
    private readonly IMemcachedClient _memcachedClient;

    public ProfileCacheWriter(IMemcachedClient memcachedClient)
    {
        _memcachedClient = memcachedClient;
    }

    public void StoreProfileSnapshot(string cacheKey, string profileJson)
    {
        // Use IMemcachedClient.Store() with separate key and value arguments.
        // The key is validated by EnyimMemcachedCore's DefaultKeyTransformer,
        // which rejects bytes 0x00-0x20 and space, preventing CRLF injection.
        _memcachedClient.Store(StoreMode.Set, cacheKey, profileJson);
    }
}
```

## Explanation

The original code hand-builds a Memcached inline-protocol command string by concatenating the untrusted `cacheKey` directly into the command. Because Memcached's inline protocol uses `\r\n` as a command delimiter, an attacker can inject `\r\n` in the key to split the current command and execute additional commands. For example, a key of `"profile:\r\nset attacker 0 0 3\r\nhax\r\n"` would inject a second `set` command.

The fix replaces the raw `Socket.Send()` with EnyimMemcachedCore's `IMemcachedClient` interface. This client library:
1. Takes the key as a separate, typed parameter in the `Store(mode, key, value)` method
2. Validates the key through its `DefaultKeyTransformer`, which throws `ArgumentException` for dangerous bytes including 0x00-0x20 (which includes `\r` and `\n`)
3. Frames the protocol commands correctly so the key cannot split a command

This eliminates the string-concatenation pattern entirely and delegates command framing to a vetted client library that understands the protocol.

## Behaviour changes

None. The `Store(StoreMode.Set, key, value)` method performs the equivalent operation to the original `set` command (store a value with no expiration, 0 flags), with identical semantics. The return type changes from `void` to `bool`, but the original code ignored network errors; a proper implementation would check the return value to handle storage failures, though that is a separate concern from the injection vulnerability.

