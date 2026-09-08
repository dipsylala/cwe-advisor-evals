## Verdict

Confirmed. `RestoreSession` reads an attacker-supplied file upload directly into a `MemoryStream` and passes it to `BinaryFormatter.Deserialize`. `BinaryFormatter` reconstructs arbitrary .NET types named inside the payload and can invoke their constructors, property setters, and `IDeserializationCallback`/`ISerializable` hooks during that process, so a crafted blob can trigger a known gadget chain and achieve remote code execution purely by being uploaded and "restored." There is no allowlist, type filter, or signature check on the incoming bytes before they reach the sink.

## Source

`blob` (the `[FromForm] IFormFile` parameter of `RestoreSession`) is the attacker-controlled source: its bytes are copied verbatim into `stream` and flow unmodified into `formatter.Deserialize(stream)` at line 29, with no validation, allowlisting, or type restriction in between.

## Fix

### File: BinaryFormatterCacheRead.cs
```csharp
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Memory;

namespace EvalCases.Controllers
{
    public class SessionData
    {
        public string UserId { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; }
        public Dictionary<string, string> Attributes { get; set; } = new();
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
        public async Task<IActionResult> RestoreSession([FromForm] IFormFile blob)
        {
            using var stream = new MemoryStream();
            await blob.CopyToAsync(stream);
            stream.Position = 0;

            SessionData? session;
            try
            {
                session = await JsonSerializer.DeserializeAsync<SessionData>(stream);
            }
            catch (JsonException)
            {
                return BadRequest("Invalid session payload.");
            }

            if (session is null)
            {
                return BadRequest("Invalid session payload.");
            }

            _cache.Set("session", session);
            return Ok();
        }
    }
}
```

## Explanation

`BinaryFormatter` is a polymorphic, type-name-driven deserializer: the byte stream itself dictates which .NET type gets instantiated and which of its members get populated, which is exactly what lets a malicious upload chain together otherwise-unrelated types into remote code execution. There is no safe way to "validate" a binary-formatted blob before deserializing it, because the type resolution and object construction happen as an intrinsic part of the deserialization call itself — the vulnerability is in the mechanism, not in a missing check on the input.

The fix removes `BinaryFormatter` from the code path entirely and replaces it with `System.Text.Json`, deserializing into a fixed, application-defined `SessionData` class instead of an open-ended `object`. `System.Text.Json` does not perform polymorphic type resolution from the payload by default: the target type is the one named in the code (`SessionData`), the deserializer only ever populates the public properties that type declares, and it does not invoke arbitrary constructors, setters, or callback interfaces belonging to attacker-chosen types. This closes the deserialization-of-untrusted-data weakness because the attacker's file can, at most, supply values for `UserId`, `CreatedAt`, and `Attributes` — it can no longer choose *what kind of object* gets built or *what code path* runs while building it. A `JsonException` from a malformed or mistyped payload is caught and turned into a `400 Bad Request` rather than propagating as an unhandled exception, and a `null` deserialization result is also rejected before it reaches the cache. The `CopyToAsync`/`DeserializeAsync` change keeps the request path non-blocking; it is not part of the security fix but avoids introducing synchronous I/O over an unbounded upload while making the other change.
