## Verdict

Exploitable. `RestoreSession` reads an attacker-supplied multipart upload directly into `BinaryFormatter.Deserialize()` with no integrity check, type restriction, or validation of any kind.

## Source

`IFormFile blob`, bound via `[FromForm]` on the `POST api/[controller]/restore` action - the raw bytes of a client-supplied file upload, fully attacker-controlled. The bytes are copied verbatim into a `MemoryStream` (lines 23-25) and reach the sink unmodified; there is no intermediate validation, signature check, or type gate anywhere in the method.

## Fix

### File: BinaryFormatterCacheRead.cs

```csharp
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
            using var stream = new MemoryStream();
            blob.CopyTo(stream);
            stream.Position = 0;

            Dictionary<string, JsonElement> session = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(stream);

            _cache.Set("session", session);
            return Ok();
        }
    }
}
```

## Explanation

`BinaryFormatter.Deserialize()` reconstructs arbitrary .NET types named inside the payload and can invoke their constructors and property setters during that process, so a crafted upload can drive gadget chains into remote code execution; Microsoft states there is no configuration that makes `BinaryFormatter` safe to use on untrusted input, so the fix removes it rather than attempting to constrain it. The replacement, `System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, JsonElement>>`, parses the stream as data only - it never resolves a type name from the payload or invokes arbitrary constructors, so a malicious upload can produce at most a JSON structure, not code execution. `Dictionary<string, JsonElement>` keeps the same "arbitrary bag of session data" shape the original `object session` implied, without granting the deserializer the ability to instantiate an attacker-chosen type. This is a wire-format change: whatever originally wrote this blob as .NET binary-serialized data (a producer outside this file) must be updated to write JSON instead, or the migration will reject every previously-stored payload - that update is not part of this diff and needs to be coordinated with wherever the blob is produced.

## Behaviour changes

- Wire format changes from .NET binary serialization to JSON. This is required by the fix itself (no safe configuration of `BinaryFormatter` exists per the loaded C# guidance) but is a breaking change for any out-of-scope producer that still writes `BinaryFormatter`-serialized blobs; that producer is not visible in this file and must be migrated separately.
- The static/declared type held in `session` and cached under `"session"` changes from an unconstrained `object` (BinaryFormatter can materialize any type present in the payload) to `Dictionary<string, JsonElement>`. This is necessary: committing to a known, non-polymorphic type is exactly what removes the attacker's ability to choose what gets constructed. Any code elsewhere that reads `"session"` back out of `_cache` and casts it to a specific business type will need to be updated to read from the dictionary instead - that call site is outside the file provided for this finding and could not be verified.
- Malformed or non-JSON input now throws `System.Text.Json.JsonException` from `JsonSerializer.Deserialize`, uncaught, exactly as malformed binary input previously threw `SerializationException` from `BinaryFormatter.Deserialize` uncaught - both propagate to ASP.NET Core's default error handling. Failure behaviour is unchanged.
- The compiler additionally flags (warning, not error) that `JsonSerializer.Deserialize` may return `null` for a `dictionary`-typed variable declared non-nullable; this is a pre-existing nullable-annotation warning class, not a new defect, and was left as-is to keep the diff minimal - a caller relying on `_cache.Get<Dictionary<string, JsonElement>>("session")` should already handle a possible `null`.

## Verification

Compiled with `dotnet build` (.NET 10 SDK, the only SDK available in this environment) inside a scratch ASP.NET Core Web API project containing this controller file, `Microsoft.AspNetCore.Mvc`, and `Microsoft.Extensions.Caching.Memory` references. Build succeeded with 0 errors; the only diagnostic on the changed line was the expected `CS8600` nullable-assignment warning discussed above. Every new symbol used - `System.Text.Json.JsonSerializer.Deserialize<TValue>(Stream, ...)`, `System.Text.Json.JsonElement`, and `System.Collections.Generic.Dictionary<TKey,TValue>` - is a .NET base class library member (no third-party package required), matching the C#-specific guidance's recommendation of `System.Text.Json` as the safe replacement.

Assumptions:
- The case file does not include a `.csproj`, so the target framework moniker (TFM) could not be confirmed. The C# guidance notes `BinaryFormatter` is fully exploitable through .NET 8 but throws unconditionally from .NET 9 onward. Because the finding was reported as reachable and the code otherwise reflects a live, deployed ASP.NET Core controller, this fix assumes a pre-.NET 9 TFM (or .NET Framework's ASP.NET Core-compatible target) where the sink is live; if the project in fact targets .NET 9+, the original code would already fail at runtime rather than being exploitable, and this fix is still correct but not urgent.
- The concrete shape of the cached "session" data is not defined anywhere in the provided file, so `Dictionary<string, JsonElement>` was chosen as the closest safe equivalent to the original's unconstrained `object`. If a specific session schema exists elsewhere in the application, replacing the dictionary with a concrete DTO type and `JsonSerializer.Deserialize<SessionDto>` would be preferable and should be done by whoever owns that schema.
- The producer of the uploaded blob (whatever previously wrote it via `BinaryFormatter`) is outside the provided file and was not identified; migrating it to emit JSON is a required companion change this fix cannot make.
