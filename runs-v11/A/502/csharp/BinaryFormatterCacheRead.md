## Verdict

**Confirmed.** Line 29 uses `BinaryFormatter.Deserialize()` on untrusted data from a user-uploaded file, creating a CWE-502 deserialization vulnerability.

## Source

The vulnerability exists in the `RestoreSession` endpoint at line 21-29:

```csharp
[HttpPost("restore")]
public IActionResult RestoreSession([FromForm] IFormFile blob)
{
    using var stream = new MemoryStream();
    blob.CopyTo(stream);
    stream.Position = 0;

    var formatter = new BinaryFormatter();
    var session = formatter.Deserialize(stream);  // Line 29: Untrusted deserialization
    
    _cache.Set("session", session);
    return Ok();
}
```

The data flow: user upload (IFormFile) → memory stream → BinaryFormatter.Deserialize(). BinaryFormatter is inherently unsafe for untrusted input because it can instantiate and invoke arbitrary types during deserialization.

## Fix

Replace `BinaryFormatter` with `System.Text.Json` for safe serialization:

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
            try
            {
                using var stream = new MemoryStream();
                blob.CopyTo(stream);
                stream.Position = 0;

                using var reader = new StreamReader(stream);
                var json = reader.ReadToEnd();

                var options = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };
                var session = JsonSerializer.Deserialize<SessionData>(json, options);

                if (session == null)
                {
                    return BadRequest("Invalid session data");
                }

                _cache.Set("session", session);
                return Ok();
            }
            catch (JsonException)
            {
                return BadRequest("Invalid JSON format");
            }
        }
    }

    public class SessionData
    {
        // Define properties for expected session data
        public string UserId { get; set; }
        public string SessionToken { get; set; }
    }
}
```

## Explanation

`BinaryFormatter` is unsafe by design—it can deserialize any .NET type and execute code during the instantiation process. An attacker can craft a malicious binary payload that instantiates dangerous types (like those in `System.Diagnostics.Process`) and compromise the server.

The fix substitutes `System.Text.Json`, which:

1. Only deserializes into explicitly defined types (SessionData), preventing arbitrary instantiation
2. Does not invoke constructors or methods during deserialization unless explicitly configured
3. Validates the input format before creating objects
4. Is the modern, maintainable standard in .NET 5+

The `JsonSerializerOptions.PropertyNameCaseInsensitive` option accommodates varying JSON casing from clients. The `SessionData` class schema-restricts what fields are accepted, rejecting unexpected input. Error handling catches malformed JSON and returns appropriate HTTP responses without exposing details.

If binary formats are required, use `MessagePack` or `Protobuf` with explicit type registration rather than BinaryFormatter.
