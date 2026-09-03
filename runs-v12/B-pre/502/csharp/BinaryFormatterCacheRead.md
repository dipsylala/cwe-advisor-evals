## Verdict

Exploitable

## Source

Untrusted serialized data from user-supplied `IFormFile` uploaded via HTTP POST endpoint, passed to `blob.CopyTo(stream)` at lines 23-25.

## Fix

**Vulnerable code (line 27-29):**
```csharp
var formatter = new BinaryFormatter();
// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
var session = formatter.Deserialize(stream);
```

**Fixed code:**
```csharp
using System.Text.Json;

// Option A: If a fixed type is known (e.g., SessionData class):
var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
SessionData session;
try
{
    session = JsonSerializer.Deserialize<SessionData>(stream, options) 
        ?? throw new InvalidOperationException("Deserialization resulted in null");
}
catch (JsonException ex)
{
    return BadRequest($"Invalid session data: {ex.Message}");
}

// Option B: If dynamic deserialization is needed (use with caution):
JsonDocument doc;
try
{
    doc = JsonDocument.Parse(stream);
}
catch (JsonException ex)
{
    return BadRequest($"Invalid JSON: {ex.Message}");
}
var session = doc.RootElement;
```

Use Option A if the session type is known; Option B only if the structure is truly dynamic and requires additional type validation before use.

## Explanation

`BinaryFormatter` enables remote code execution on untrusted data because .NET deserialization can instantiate arbitrary types and invoke methods during object graph reconstruction. The formatter cannot be made secure regardless of configuration. System.Text.Json replaces this with safe JSON deserialization that instantiates only the declared type, preventing arbitrary code execution. Option A (strongly typed) is preferred because it constrains the payload to expected fields only; Option B (dynamic) trades type safety for flexibility and requires the calling code to validate the structure before passing it to cache or other operations.

## Behaviour changes

**Serialization format change**: The fix changes the expected input format from .NET binary serialized data to JSON. This is a breaking change for clients - they must serialize to JSON instead of using BinaryFormatter.

**Type safety**: The fix adds explicit type checking. Option A will throw `JsonException` on malformed input or `InvalidOperationException` if deserialization returns null, both caught and returned as `BadRequest`. The original code would throw `SerializationException` from BinaryFormatter on invalid input, which also results in an error response but with different exception details.

**Response on error**: Both the original and fixed code will return an error response on invalid input. The fixed code explicitly returns `BadRequest` with an error message rather than allowing an unhandled exception, which is a safety improvement.

**JSON property naming**: The options set `PropertyNameCaseInsensitive = true` to handle common JSON casing variations. Adjust if the client-side serialization follows strict C# naming conventions.

No other functional behavior changes when valid JSON matching the expected type is provided.
