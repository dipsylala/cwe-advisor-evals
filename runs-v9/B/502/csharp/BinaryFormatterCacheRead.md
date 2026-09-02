## Verdict

Exploitable. Confidence: high.

`RestoreSession` deserializes an attacker-supplied file upload with `BinaryFormatter`, which .NET's own documentation states cannot be made secure at any configuration — this is remote code execution via arbitrary type instantiation during deserialization, not a hardening gap. No target framework file (`.csproj`) was provided with this finding; the fix removes `BinaryFormatter` outright rather than relying on its removed/obsolete status on newer .NET versions, since `System.Runtime.Serialization.Formatters.Binary` still compiles and runs on .NET Framework 4.8 and on .NET up to 8 with an opt-in switch, and the guidance is explicit that there is no safe configuration to fall back on regardless of runtime.

## Source

- **Source**: the `blob` parameter of `POST api/SessionCache/restore`, bound via `[FromForm] IFormFile` — an HTTP request body supplied by an unauthenticated (or at least unvalidated) caller, copied verbatim into a `MemoryStream`.
- **Sink**: `formatter.Deserialize(stream)` at line 29, using `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`.
- **Flow**: the uploaded bytes reach the sink with no type check, signature check, or content validation between the copy at line 24 and the deserialize call at line 29. The result is stored in `IMemoryCache` under the key `"session"` and later consumed elsewhere as though it were a trusted session object — so a crafted upload can substitute a gadget chain for the expected type and get code execution the moment `Deserialize` walks the payload, before any application logic runs.

## Fix

Vulnerable code (`BinaryFormatterCacheRead.cs`, lines 1–35):

```csharp
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
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

            var formatter = new BinaryFormatter();
            // SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
            var session = formatter.Deserialize(stream);

            _cache.Set("session", session);
            return Ok();
        }
    }
}
```

Fixed code:

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

            // System.Text.Json only ever populates the declared type's own
            // members - it cannot be told to construct an arbitrary type
            // from the payload, which is what made BinaryFormatter unsafe.
            var session = JsonSerializer.Deserialize<SessionData>(stream);

            _cache.Set("session", session);
            return Ok();
        }
    }

    // Placeholder: replace with the actual fields the cached session object
    // needs to carry. The original file never defines the type BinaryFormatter
    // was reconstructing, so its real shape has to come from the rest of the
    // codebase (wherever _cache.Get("session") is later read back).
    public class SessionData
    {
    }
}
```

## Explanation

The weakness is `BinaryFormatter.Deserialize` walking attacker-controlled bytes and instantiating whatever type the payload names, which is how a crafted upload turns into code execution rather than data. The fix replaces the formatter with `System.Text.Json.JsonSerializer.Deserialize<SessionData>`, which only ever binds JSON properties onto the members of the compile-time-fixed `SessionData` type — the payload can supply field values but can never choose what class gets constructed or trigger arbitrary code as a side effect of deserializing. Everything else in the method — the stream setup, the `IMemoryCache.Set` call, the return value — is unchanged, so the fix is scoped to the sink itself: swap the unsafe formatter for a safe one operating on a known type, per the loaded C# guidance's core remediation ("avoid deserializing untrusted data entirely, or use safe serializers like System.Text.Json with strict type controls"). `SessionData` is left as an empty placeholder because the real session shape is never defined in this file; a developer applying this fix needs to populate it with the fields the rest of the application actually reads from the cached `"session"` value.

## Behaviour changes

- **Wire format changes from a .NET binary-serialized blob to JSON.** This is unavoidable — there is no safe configuration of `BinaryFormatter` to keep, per the loaded guidance — but it means existing clients that POST a `BinaryFormatter`-serialized payload to this endpoint must be updated to send JSON instead. Flagging this as a compatibility break for review, not something to apply silently against a live client.
- **The constructible type is now fixed to `SessionData` instead of attacker-chosen.** This is the fix itself, not incidental scope creep: the original vulnerability was precisely that the payload controlled which type got built.
- **`SessionData` is an empty placeholder type.** Its real members are not visible in the provided file (they were never defined here even in the vulnerable version — `session` was `object`), so this fix cannot recover the original data contract on its own; the field list must be filled in from how the cached `"session"` entry is consumed elsewhere before this is production-ready.
- **Failure mode on malformed input is `JsonException` instead of `SerializationException`.** Neither the original nor the fixed code catches this, so both surface as an unhandled exception (a 500 response) on invalid input — no functional change in error handling, just a different exception type.
- No changes to the method signature, stream handling, cache key, or return value.
