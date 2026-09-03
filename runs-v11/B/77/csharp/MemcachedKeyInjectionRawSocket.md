## Verdict

**CONFIRMED**: CWE-77 command injection vulnerability. The `cacheKey` parameter from an untrusted source (upstream request header) is directly concatenated into a memcached inline protocol command without validation. An attacker can inject CRLF (`\r\n`) or spaces to break out of the key field and inject additional commands, alter the command structure, or cause protocol errors.

## Source

The vulnerable data flow:
- **Origin**: `cacheKey` parameter at line 18 (originates from upstream request header)
- **Sink**: `_memcachedSocket.Send(payload)` at line 26
- **Unsafe construction**: String concatenation at lines 21-22 directly embeds untrusted input into the memcached command string without validation

The memcached inline protocol uses space (0x20) as a field delimiter and CRLF (`\r\n`) as the command terminator. These are special characters in the protocol syntax; embedding them in the key field breaks the protocol boundary.

## Fix

Validate the `cacheKey` to reject control characters and spaces (byte values 0x00-0x20, inclusive). This matches the default defence that EnyimMemcachedCore's `DefaultKeyTransformer` enforces.

```csharp
public void StoreProfileSnapshot(string cacheKey, string profileJson)
{
    // Validate cacheKey - reject control characters and whitespace (0x00-0x20)
    if (string.IsNullOrEmpty(cacheKey))
    {
        throw new ArgumentException("Cache key cannot be null or empty.", nameof(cacheKey));
    }

    foreach (char c in cacheKey)
    {
        if ((int)c <= 0x20)
        {
            throw new ArgumentException(
                $"Cache key contains invalid character (byte 0x{(int)c:X2}). Keys must not contain control characters or whitespace.",
                nameof(cacheKey));
        }
    }

    byte[] value = Encoding.ASCII.GetBytes(profileJson);
    string command = "set " + cacheKey + " 0 0 " + value.Length +
        "\r\n" + profileJson + "\r\n";
    byte[] payload = Encoding.ASCII.GetBytes(command);

    _memcachedSocket.Send(payload);
}
```

## Explanation

The fix validates the `cacheKey` before it is concatenated into the command string. The validation rejects any byte in the range 0x00-0x20 (decimal), which includes all control characters (CR, LF, tab, etc.) and space. These are the exact bytes that are special in the memcached inline protocol and could allow an attacker to inject commands or break protocol boundaries.

The validation is applied at the entry point of the method, ensuring no untrusted key reaches the string-building logic. If an invalid key is provided, an `ArgumentException` is thrown with a clear message identifying the invalid byte value. Legitimate keys (alphanumeric, punctuation except space) pass through unchanged.

This approach is defence-in-depth and aligns with the CWE-77 remediation guidance: "Allowlist the expected format rather than denylisting metacharacters" - here we allowlist characters by rejecting the known-dangerous set of control characters and delimiters.

## Behaviour changes

**Before the fix:**
- Invalid or malicious keys containing CRLF, spaces, or other control characters were accepted and embedded directly into the memcached protocol command, allowing command injection or protocol disruption.

**After the fix:**
- Any call to `StoreProfileSnapshot()` with a key containing bytes 0x00-0x20 will throw an `ArgumentException` instead of silently accepting the invalid input.
- Legitimate keys (those without control characters or spaces) continue to work as before, with no change in behavior.
- Invalid keys are rejected at the API boundary, preventing malformed commands from being sent to memcached.

**Testing notes:**
- Confirm that injection attempts like `"key\r\nSET admin"` are rejected.
- Confirm that values containing CRLF or spaces in the *data* block (the `profileJson` parameter) are still stored correctly - the fix only validates the key, not the value.
- Verify that legitimate keys like `"profile:tenant123"`, `"user-data.123"` continue to work.
