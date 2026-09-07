## Verdict

**VULNERABLE** → **REMEDIABLE**

BinaryFormatter.Deserialize() at line 29 accepts untrusted user-uploaded data without type restrictions or integrity checks, enabling arbitrary type instantiation and remote code execution.

## Source

**Input:** User-supplied file uploaded via HTTP form (`[FromForm] IFormFile blob`)

**Data flow:** 
```
blob (untrusted) → MemoryStream → BinaryFormatter.Deserialize(stream) → cached session object
```

**Attack surface:** Any developer or third party able to call `/api/sessioncache/restore` can upload a malicious serialized object that instantiates arbitrary types during deserialization, executing attacker-controlled code.

## Fix

**Vulnerable code (line 27–29):**
```csharp
var formatter = new BinaryFormatter();
// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
var session = formatter.Deserialize(stream);
```

**Fixed code:**
```csharp
// Define a concrete type for session data with known, safe properties
public class SessionData
{
    public string? UserId { get; set; }
    public string? Username { get; set; }
    // Include only session fields explicitly needed by the application
}

// In RestoreSession method, replace lines 27-29 with:
try
{
    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
    var session = JsonSerializer.Deserialize<SessionData>(stream, options);
    
    if (session == null)
    {
        return BadRequest("Invalid session data");
    }

    _cache.Set("session", session);
    return Ok();
}
catch (JsonException ex)
{
    return BadRequest($"Invalid session format: {ex.Message}");
}
```

**Required imports:**
- `System.Text.Json` (built into .NET 5+)
- Remove `using System.Runtime.Serialization.Formatters.Binary;`

## Explanation

BinaryFormatter is unsafe by design—Microsoft's own security advisory states it cannot be made secure and should not be used for untrusted data. The fix replaces it with System.Text.Json, which:

1. **Enforces strict type control:** The generic `Deserialize<SessionData>` parameter constrains deserialization to only the SessionData type and its safe properties. Attackers cannot force instantiation of arbitrary types (gadgets).

2. **Switches to JSON format:** JSON is text-based and cannot contain executable payloads. It requires explicit schema definition (the SessionData class), which acts as a whitelist of deserializable fields.

3. **Adds validation:** The null check and exception handling ensure malformed input is rejected cleanly rather than triggering deserialization attempts.

4. **Applies input validation after deserialization:** The returned object is checked before use, closing any remaining gap between parsing and consumption.

The swap from binary to JSON is a breaking change in wire format. Producers (session serializers upstream) must be updated to emit JSON instead of binary. This is appropriate for this scenario because BinaryFormatter has no safe mode—format migration is the only viable path forward.

## Behaviour changes

- **Input format:** Changes from binary serialization to JSON. Clients must send `Content-Type: application/json` and provide session data as JSON.
- **Failure mode:** Invalid data now returns HTTP 400 with a descriptive error message instead of potentially triggering deserialization exceptions deep in the formatter.
- **Caching:** The cached object is now strictly SessionData type instead of object, improving type safety in downstream consumers.
- **Wire protocol breaking change:** Any existing clients sending binary-serialized sessions will fail. Clients must be updated to send JSON.
