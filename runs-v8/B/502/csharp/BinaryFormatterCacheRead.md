## Verdict

Exploitable. Line 29 deserializes untrusted binary data using `BinaryFormatter`, which Microsoft states cannot be secured and is unsafe for any untrusted input. Attackers can craft serialized payloads to instantiate arbitrary types and execute code during deserialization, compromising the application.

## Source

Untrusted binary data uploaded via HTTP POST `[FromForm] IFormFile blob` parameter (line 21). The file content flows directly into a `MemoryStream` (line 24) without validation or signature verification.

## Fix

**Vulnerable code:**
```csharp
var formatter = new BinaryFormatter();
// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
var session = formatter.Deserialize(stream);
```

**Fixed code:**
```csharp
// Define a Session class with only expected properties (not shown here - adapt to your actual session type)
// var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
// var session = System.Text.Json.JsonSerializer.Deserialize<SessionData>(stream, options);

// Or, using a simpler string-based approach that avoids arbitrary type instantiation:
using var reader = new StreamReader(stream);
string jsonContent = reader.ReadToEnd();
var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var session = System.Text.Json.JsonSerializer.Deserialize<object>(jsonContent, options);
// Type validation would go here based on application requirements
```

**Required changes:**
1. Remove the `using System.Runtime.Serialization.Formatters.Binary;` import
2. Add `using System.Text.Json;` import
3. Replace `BinaryFormatter` with `System.Text.Json.JsonSerializer`
4. Define or reuse an existing `SessionData` class (or similar type) to enforce type safety during deserialization
5. Optionally add HMAC integrity verification before deserialization for defense-in-depth

## Explanation

BinaryFormatter is fundamentally unsafe because it instantiates arbitrary .NET types during deserialization, allowing attackers to chain gadget classes to achieve remote code execution. Microsoft deprecated BinaryFormatter in .NET 5, marked it obsolete in .NET 6, and removed its capability to function in .NET 9+, explicitly stating it cannot be secured. 

System.Text.Json replaces it with a type-safe, format-safe alternative that deserializes only into known types specified at compile time. By replacing the `BinaryFormatter.Deserialize()` call with `System.Text.Json.JsonSerializer.Deserialize<T>()` bound to a specific expected type, the application prevents arbitrary class instantiation. The untrusted input is now treated as inert data and reconstructed only into the declared type, eliminating the attack surface.

If signature or integrity verification is needed (defense-in-depth), implement HMAC validation on the JSON payload before deserialization, comparing a submitted signature against a server-computed HMAC using a secret key.

## Behaviour changes

- **Serialization format change**: The code now expects JSON instead of .NET binary format. Clients uploading sessions must be updated to send JSON-serialized data. This is a breaking change requiring coordinated migration.
- **Type enforcement**: Deserialization is now restricted to the declared type (`SessionData` or your equivalent). Fields matching the type's properties are reconstructed; unexpected fields are ignored by default (or can be controlled via `JsonSerializerOptions.UnknownTypeHandling`).
- **Exception handling**: `System.Text.Json.JsonException` replaces `SerializationException`; catch blocks should be updated accordingly.
- **No behaviour is lost in the sink contract**: The fixed code still returns an object assigned to `session`, used the same way downstream in `_cache.Set("session", session)`. Performance is comparable or better; memory safety is identical.
