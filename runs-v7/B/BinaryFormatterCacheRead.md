## Verdict

Confirmed CWE-502 vulnerability. `BinaryFormatter.Deserialize()` at line 29 deserializes untrusted data from a user-supplied form file, enabling arbitrary type instantiation and remote code execution. Microsoft explicitly states that BinaryFormatter cannot be secured and must be removed.

## Source

File: `BinaryFormatterCacheRead.cs`, line 29.

The vulnerability originates when `RestoreSession()` receives user-controlled serialized data via `[FromForm] IFormFile blob`, passes it through a memory stream, and deserializes it using `BinaryFormatter` without any type restrictions or integrity validation. The deserialized object is then stored in the cache.

Data flow: User input (blob) → MemoryStream → BinaryFormatter.Deserialize() (sink) → cache storage.

## Fix

Replace `BinaryFormatter` with `System.Text.Json` and define an explicit model class for type-safe deserialization:

```csharp
using System;
using System.IO;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace EvalCases.Controllers
{
    public class SessionData
    {
        public string UserId { get; set; }
        public DateTime Timestamp { get; set; }
        // Define only fields required for the session data
    }

    [ApiController]
    [Route("api/[controller]")]
    public class SessionCacheController : ControllerBase
    {
        private readonly IMemoryCache _cache;

        public SessionCacheController(IMemoryCache cache)
        {
            _cache = cache;
        }

        [HttpPost("restore")]
        public IActionResult RestoreSession([FromForm] IFormFile blob)
        {
            try
            {
                using var stream = new MemoryStream();
                blob.CopyTo(stream);
                stream.Position = 0;

                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var session = JsonSerializer.Deserialize<SessionData>(stream, options);

                if (session == null)
                {
                    return BadRequest("Invalid session data");
                }

                _cache.Set("session", session);
                return Ok();
            }
            catch (JsonException)
            {
                return BadRequest("Malformed session data");
            }
        }
    }
}
```

## Explanation

BinaryFormatter is fundamentally unsafe according to Microsoft security guidance (removed in .NET 9, obsoleted in .NET 5). It can instantiate arbitrary types during deserialization, allowing attackers to trigger code execution through gadget chains in the .NET runtime or available dependencies.

`System.Text.Json` mitigates this by:
1. Requiring an explicit target type at deserialization time, restricting which classes can be instantiated
2. Deserializing only to publicly settable properties matching the JSON structure
3. Refusing to instantiate types dynamically based on the payload

The fix introduces a `SessionData` class that explicitly defines which fields are permitted in a session. Only JSON payloads matching this structure are accepted; malicious payloads attempting to instantiate other types are rejected at deserialization.

## Behaviour changes

- Session data must now be JSON-formatted instead of binary-serialized
- Only fields present in the `SessionData` class are deserialized; extra fields are ignored
- Malformed or non-JSON payloads trigger a 400 Bad Request response instead of potentially executing arbitrary code
- The session is restricted to the defined `SessionData` type, preventing type confusion attacks
- If session integrity is critical, add HMAC-based validation (sign the JSON with a server-held key before sending to clients, verify the signature before deserialization)
