## Verdict
Exploitable

## Source
HTTP form file upload (`IFormFile blob` parameter) - attacker-controlled

## Fix
Replace `BinaryFormatter` with `System.Text.Json` to safely deserialize untrusted data with strong typing. Add exception handling for malformed input. Require JSON format instead of binary format for all producers.

### File: BinaryFormatterCacheRead.cs
```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
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
                // Use System.Text.Json instead of BinaryFormatter to safely deserialize untrusted data
                var json = Encoding.UTF8.GetString(stream.ToArray());
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

                // Deserialize to a known type (Dictionary) rather than object
                var session = JsonSerializer.Deserialize<Dictionary<string, object>>(json, options);

                if (session == null)
                {
                    return BadRequest("Invalid session format");
                }

                _cache.Set("session", session);
                return Ok();
            }
            catch (JsonException)
            {
                return BadRequest("Session data must be valid JSON");
            }
        }
    }
}
```

## Explanation
The original code used `BinaryFormatter.Deserialize()` which is unsafe: it can instantiate arbitrary types during deserialization, enabling remote code execution through gadget chains. BinaryFormatter is obsolete from .NET 5 and throws on .NET 9+. The fix replaces it with `System.Text.Json`, which is safe by design—it does not execute code or instantiate arbitrary types. The deserialization target is now explicitly typed as `Dictionary<string, object>` instead of `object`, enforcing type safety. The fix adds exception handling to catch malformed JSON and return a 400 Bad Request instead of throwing. This closes the vulnerability entirely: the attacker cannot execute code through JSON deserialization, and the type system constrains what can be constructed.

## Behaviour changes
- Input format changes from binary to JSON (breaking change for existing binary producers; all callers and producers must switch to JSON format)
- Return type is now `Dictionary<string, object>` instead of an arbitrary object type
- Invalid input now returns HTTP 400 with error message instead of throwing an unhandled exception
- Requires .NET Core 3.1+ or .NET 5+ (System.Text.Json is built-in to these frameworks)
