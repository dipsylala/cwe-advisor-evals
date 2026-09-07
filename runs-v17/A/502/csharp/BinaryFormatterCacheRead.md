## Verdict
VULNERABLE. The code deserializes untrusted data (from user-uploaded file) using BinaryFormatter, which can instantiate arbitrary types and execute attacker-controlled code.

## Source
File: BinaryFormatterCacheRead.cs
Line: 29
Issue: `var session = formatter.Deserialize(stream);`

The method receives untrusted data via `[FromForm] IFormFile blob`, reads it into a stream, and passes it directly to `BinaryFormatter.Deserialize()` without any type restrictions or validation. BinaryFormatter can reconstruct any serializable .NET type, making this an RCE vector.

## Fix

### File: BinaryFormatterCacheRead.cs
```csharp
using System;
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
            using var stream = new MemoryStream();
            blob.CopyTo(stream);
            stream.Position = 0;

            try
            {
                // Use JSON deserialization instead of BinaryFormatter to avoid arbitrary type instantiation
                using var doc = JsonDocument.Parse(stream);
                _cache.Set("session", doc.RootElement.Clone());
                return Ok();
            }
            catch (JsonException)
            {
                return BadRequest("Invalid session format");
            }
        }
    }
}
```

## Explanation
The fix replaces BinaryFormatter with System.Text.Json, which is a safe alternative for this scenario:

1. **Removed BinaryFormatter**: Eliminated the dangerous built-in serializer that can instantiate arbitrary types without restrictions.

2. **Replaced with JsonDocument.Parse()**: JSON deserialization inherently limits what can be instantiated - it can only create basic types (strings, numbers, arrays, objects) without custom type construction.

3. **JsonElement safety**: The deserialized JsonElement is type-restricted and cannot trigger arbitrary code execution through gadget chains.

4. **Error handling**: Added try-catch to handle malformed JSON gracefully, returning a 400 Bad Request instead of crashing or silently accepting invalid data.

5. **Maintained cache storage**: The cloned JsonElement is stored in the cache just like the original object, preserving the intended functionality.

This prevents CWE-502 by ensuring that only well-formed JSON data can be deserialized, and only primitive JSON types and objects can be reconstructed - not arbitrary .NET types that could contain malicious payload gadgets.
