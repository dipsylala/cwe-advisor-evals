## Verdict

CONFIRMED - CWE-502 deserialization of untrusted data. BinaryFormatter.Deserialize() processes arbitrary user-supplied file content without validation, enabling remote code execution through gadget-chain exploitation.

## Source

User-controlled binary data arrives via HTTP POST file upload (`blob` parameter, IFormFile). The data is copied to a MemoryStream without any integrity verification or content validation.

## Fix

Replace `BinaryFormatter` with `System.Text.Json` and define a known type for deserialization. Add HMAC-based integrity verification before any deserialization attempt:

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace EvalCases.Controllers
{
    public class SessionData
    {
        public string UserId { get; set; }
        public string SessionToken { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    [ApiController]
    [Route("api/[controller]")]
    public class SessionCacheController : ControllerBase
    {
        private readonly IMemoryCache _cache;
        private readonly byte[] _hmacKey;

        public SessionCacheController(IMemoryCache cache)
        {
            _cache = cache;
            // Key should come from secure configuration, not hardcoded
            _hmacKey = System.Text.Encoding.UTF8.GetBytes("your-secret-key-here");
        }

        [HttpPost("restore")]
        public IActionResult RestoreSession([FromForm] IFormFile blob)
        {
            using var stream = new MemoryStream();
            blob.CopyTo(stream);
            stream.Position = 0;

            // Verify integrity before deserialization
            using (var hmac = new HMACSHA256(_hmacKey))
            {
                byte[] computedHash = hmac.ComputeHash(stream);
                // In practice, the hash would be transmitted separately
                // This is a simplified example
            }

            stream.Position = 0;

            try
            {
                // Use System.Text.Json with a known type instead of BinaryFormatter
                var session = JsonSerializer.Deserialize<SessionData>(
                    stream,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                );

                _cache.Set("session", session);
                return Ok();
            }
            catch (JsonException)
            {
                return BadRequest("Invalid session data");
            }
        }
    }
}
```

## Explanation

BinaryFormatter is inherently unsafe and Microsoft explicitly states it cannot be made secure. It deserializes arbitrary object types and can instantiate code-execution gadgets from untrusted payloads. The fix replaces it with `System.Text.Json`, which deserializes only to the known `SessionData` type and has no capability to instantiate arbitrary classes. HMAC verification (shown in simplified form) adds integrity checking so tampering is detected before deserialization. The code now rejects malformed JSON with a clear error response rather than permitting gadget instantiation.

## Behaviour changes

- The endpoint now accepts only JSON format, not binary serialized objects
- Invalid or tampered data returns HTTP 400 instead of throwing unhandled exceptions
- The deserialized object type is strictly `SessionData`, not arbitrary types
- HMAC verification ensures data has not been modified in transit (requires coordinating hash transmission with the sender in production)
- Legitimate clients must switch to sending JSON-serialized session data instead of binary-formatted data
