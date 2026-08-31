## Verdict

Confirmed. `RestoreSession` reads an attacker-supplied file upload (`IFormFile blob`) directly into a `MemoryStream` and passes it to `BinaryFormatter.Deserialize`. `BinaryFormatter` reconstructs arbitrary .NET object graphs from the byte stream, including type instantiation and constructor/property/callback execution driven entirely by content the client controls. A crafted payload (e.g. a gadget chain built from types available on the server, such as those in `System.Windows.Data`, `System.Data`, or common third-party assemblies) can achieve remote code execution the moment `Deserialize` runs, before any application logic inspects the result. This is the canonical case of CWE-502.

## Source

- Untrusted input: the `blob` parameter of `RestoreSession`, an `IFormFile` taken straight from the HTTP request body (`[HttpPost("restore")]`, `[FromForm] IFormFile blob`). No authentication, size, content-type, or content validation is applied before the bytes reach the deserializer.
- Sink: `formatter.Deserialize(stream)` at line 29, using `System.Runtime.Serialization.Formatters.Binary.BinaryFormatter`.
- Flow: `blob` -> copied verbatim into `stream` -> `stream` handed to `BinaryFormatter.Deserialize` with no allow-list, no type filtering, and no format validation in between.

## Fix

Remove `BinaryFormatter` entirely and deserialize into a fixed, known DTO using `System.Text.Json`, which never instantiates arbitrary types from the payload.

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

        private static readonly JsonSerializerOptions SessionJsonOptions = new()
        {
            // Reject unknown/extra fields instead of silently absorbing them.
            UnmappedMemberHandling = System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow,
            // No custom converters or TypeInfoResolver are registered, so
            // deserialization can only ever produce a SessionData instance -
            // there is no mechanism here for the payload to select a type.
        };

        public SessionCacheController(IMemoryCache cache)
        {
            _cache = cache;
        }

        [HttpPost("restore")]
        public async Task<IActionResult> RestoreSession([FromForm] IFormFile blob)
        {
            const long MaxSessionBytes = 64 * 1024;
            if (blob.Length <= 0 || blob.Length > MaxSessionBytes)
            {
                return BadRequest("Invalid session payload size.");
            }

            SessionData session;
            try
            {
                await using var stream = blob.OpenReadStream();
                session = await JsonSerializer.DeserializeAsync<SessionData>(
                    stream, SessionJsonOptions, HttpContext.RequestAborted)
                    ?? throw new JsonException("Empty session payload.");
            }
            catch (JsonException)
            {
                return BadRequest("Session payload could not be parsed.");
            }

            _cache.Set("session", session);
            return Ok();
        }
    }

    // Plain data-only contract: no delegates, no polymorphic/interface-typed
    // members, nothing that lets the payload drive code execution.
    public sealed class SessionData
    {
        public string UserId { get; set; } = string.Empty;
        public DateTimeOffset IssuedAt { get; set; }
        public string[] Roles { get; set; } = Array.Empty<string>();
    }
}
```

Key points carried over into the fix:

- `BinaryFormatter` and the `System.Runtime.Serialization.Formatters.Binary` using directive are removed outright; there is no configuration of `BinaryFormatter` (e.g. a `SerializationBinder`) that is safe to use against attacker-supplied input, and Microsoft has been removing the type from the runtime rather than hardening it (it throws by default in current .NET and is being deleted in newer releases), so a version bump alone will not preserve this code path.
- `JsonSerializer.Deserialize<SessionData>` is given an explicit closed type. Unlike `BinaryFormatter`, it does not read a type name out of the payload and instantiate it - the shape of `SessionData` is fixed by the C# class, so the payload can only populate that class's own properties.
- `UnmappedMemberHandling = Disallow` rejects payloads carrying fields outside the declared contract, keeping the deserializer from being repurposed later if someone widens `SessionData` without noticing.
- A size cap (`MaxSessionBytes`) and a `BadRequest` response on malformed JSON add defense-in-depth without being the primary control - the primary control is that arbitrary-type instantiation is no longer possible.
- If the real session object graph needs polymorphism (interfaces, abstract base classes, `object`-typed members) beyond what a flat DTO like `SessionData` can express, do not restore that by adding a `JsonSerializerOptions.TypeInfoResolver`/custom converter that maps type discriminators to `Type.GetType()` or an open-ended registry - that reintroduces the same class of attacker-controlled type selection `BinaryFormatter` had. Instead, map the discriminator through a hand-written, closed `switch` over an allow-listed set of known concrete types.

## Explanation

`BinaryFormatter` does not just decode data, it directs the runtime to construct whatever object graph the byte stream encodes: types, fields, and in many cases constructors, `ISerializable` hooks, or `OnDeserialized` callbacks all execute as a side effect of `Deserialize`, using type information taken from the stream itself rather than anything the application declares. Because `RestoreSession` accepts an unauthenticated file upload as that stream, an attacker fully controls which types get instantiated - including "gadget" types already loaded in the process whose deserialization or finalization side effects can be chained into file writes, process launches, or arbitrary code execution. No amount of validating the deserialized *result* helps, because the damage happens during `Deserialize` itself, before the method returns.

The fix eliminates the vulnerable mechanism rather than trying to filter it: `System.Text.Json`'s `Deserialize<T>` is told up front exactly which CLR type to populate (`SessionData`), and it does so by mapping JSON property names onto that type's declared properties - there is no code path by which a hostile payload can cause a different type to be instantiated or a callback to fire. Combined with rejecting unrecognized fields and capping payload size, the endpoint retains its original purpose (accept a serialized session on a POST and cache it) while removing the attacker's ability to influence anything except the values of `SessionData`'s own properties.
