## Verdict

Exploitable. Untrusted file content from the HTTP request is directly deserialized using BinaryFormatter without type validation, enabling remote code execution through arbitrary .NET class instantiation.

## Source

`IFormFile blob` parameter from HTTP POST request at line 21 (`[FromForm] IFormFile blob`). This is attacker-controlled file upload data.

## Fix

**Vulnerable code (line 27-29):**
```csharp
var formatter = new BinaryFormatter();
var session = formatter.Deserialize(stream);
```

**Fixed code:**
```csharp
stream.Position = 0;
var session = System.Text.Json.JsonSerializer.Deserialize<SessionData>(stream);
```

Where `SessionData` is a concrete, known type defined in the application that represents the expected session structure. If the session type is a simple key-value store, use `Dictionary<string, object>` with `System.Text.Json.Serialization.JsonSerializerOptions` configured to reject type information in the JSON.

Alternatively, if polymorphic types are required, deserialize to `System.Text.Json.JsonDocument` and validate the structure explicitly before accessing fields:
```csharp
stream.Position = 0;
var doc = System.Text.Json.JsonDocument.Parse(stream);
// Validate doc.RootElement structure before use
var session = doc;
```

## Explanation

BinaryFormatter is unsafe for untrusted data because it instantiates arbitrary .NET types during deserialization, allowing attackers to trigger constructors, property setters, and methods on any type available in the runtime. Microsoft has deprecated and removed BinaryFormatter from .NET 5+ for this reason, stating it cannot be secured only configured less dangerously.

System.Text.Json replaces native binary deserialization with safe JSON parsing that requires an explicit, compile-time-known type. When deserializing to a specific type (the first approach), only properties of that type are populated, preventing arbitrary class instantiation. When using JsonDocument (the second approach), the deserialized content remains as structured data (JsonElement) rather than arbitrary objects, eliminating code execution during parsing.

The fix eliminates the weakness by removing the dangerous deserialization mechanism entirely and replacing it with a safe data format that does not support arbitrary type instantiation.

## Behaviour changes

- **Serialization format**: Changes from binary to JSON. Clients must serialize sessions as JSON instead of binary. This is a breaking change for existing cache entries.
- **Type instantiation**: No longer creates arbitrary .NET types. Only the target type's properties are populated. This prevents gadget-chain attacks but may reject valid binary session data from earlier versions.
- **Return type**: When using JsonDocument approach, returns JsonDocument instead of object. Calling code must navigate the JsonElement tree instead of direct property access. If using a concrete type, return type remains object-compatible.
- **Performance**: JSON parsing is generally slower than binary deserialization but acceptable for session caching. Test locally to confirm acceptable latency.
