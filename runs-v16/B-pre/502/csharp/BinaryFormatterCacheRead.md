## Verdict
exploitable

## Source
User-controlled file upload via `[FromForm] IFormFile blob` parameter in the `RestoreSession` POST endpoint. The uploaded bytes are read directly into a stream without any integrity verification.

## Fix

**Vulnerable code (line 29):**
```csharp
var formatter = new BinaryFormatter();
// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
var session = formatter.Deserialize(stream);
```

**Fixed code:**
```csharp
using var reader = new StreamReader(stream);
var jsonContent = reader.ReadToEnd();

// Use JsonDocument to parse safely without arbitrary type instantiation
var doc = JsonDocument.Parse(jsonContent);
// The session data is now parsed as JSON without triggering code execution

_cache.Set("session", doc.RootElement.Clone());
```

**Required changes:**
- Remove `using System.Runtime.Serialization.Formatters.Binary;`
- Add `using System.Text.Json;` (already available in .NET 5+)
- Replace the `BinaryFormatter.Deserialize()` call with `JsonDocument.Parse()`
- Store the parsed JSON element instead of the deserialized object

## Explanation
`BinaryFormatter` is fundamentally unsafe for untrusted data because it instantiates arbitrary types during deserialization, enabling remote code execution. Microsoft explicitly states `BinaryFormatter` cannot be made secure and recommends complete removal. The fix replaces it with `System.Text.Json`'s `JsonDocument.Parse()`, which parses JSON as data structures without invoking any type constructors. The parsed JSON element is stored in the cache rather than an arbitrary deserialized object, preventing attackers from crafting serialized payloads that execute code during deserialization. This eliminates the entire attack surface for this vulnerability.

## Behaviour changes
- **Format change**: The serialized data format changes from binary to JSON. Callers uploading binary-serialized data will need to be updated to send JSON instead. This is a breaking change that reflects the replacement of an unsafe format with a secure one.
- **Cached object type**: The cached value changes from a deserialized CLR object to a `JsonElement`. Code reading from the cache will need to navigate the JSON structure via `JsonElement` properties rather than CLR object properties.
- **Implicit imports removed**: The `using System.Runtime.Serialization.Formatters.Binary;` import is no longer needed and should be removed.
- **Implicit imports added**: `System.Text.Json` is a standard library namespace in .NET 5+ and does not require a package dependency.
