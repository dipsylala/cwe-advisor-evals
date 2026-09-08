## Verdict
Exploitable

## Source
- **Source**: Line 21 - `blob` parameter from `[FromForm] IFormFile blob`; user uploads untrusted binary file
- **Sink**: Line 29 - `formatter.Deserialize(stream)` on BinaryFormatter
- **Data Flow**: Attacker-controlled file bytes are copied to MemoryStream and passed directly to BinaryFormatter.Deserialize without validation, integrity checks, or type constraints

## Fix

### File: BinaryFormatterCacheRead.cs

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace EvalCases.Controllers
{
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
            using var stream = new StreamReader(blob.OpenReadStream());
            var json = stream.ReadToEnd();

            var options = new JsonSerializerOptions 
            { 
                PropertyNameCaseInsensitive = true 
            };
            var session = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

            _cache.Set("session", session);
            return Ok();
        }
    }
}
```

## Explanation
BinaryFormatter is fundamentally unsafe because it instantiates arbitrary types specified within the binary payload, giving attackers complete control over object construction and enabling remote code execution. The fix replaces BinaryFormatter.Deserialize with System.Text.Json.Deserialize, which is safe by design: it requires an explicit target type and does not support arbitrary type instantiation. The input format changes from binary to JSON, which is acceptable here because the data originates from an untrusted client (the file upload), so format negotiation is not a constraint. Deserializing into Dictionary<string, object> constrains the output to a flat key-value structure with primitive values, eliminating the attack surface. The built-in PropertyNameCaseInsensitive option matches typical session serialization patterns without introducing security risk.

## Behaviour changes
- **Input format change**: blob is now expected to be JSON rather than binary. This is intentional and necessary to eliminate the arbitrary type instantiation attack.
- **Stream reading**: The stream is now read as text via StreamReader instead of passed directly to a binary formatter. Required for JSON parsing.
- **Type constraint**: Output is now Dictionary<string, object> rather than the arbitrary object type that BinaryFormatter could produce. This prevents attacker-controlled type instantiation.
