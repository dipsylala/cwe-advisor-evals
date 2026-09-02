## Verdict

Confirmed. `RestoreSession` reads an attacker-supplied file upload (`IFormFile blob`) into a stream and passes it directly to `BinaryFormatter.Deserialize`. `BinaryFormatter` reconstructs arbitrary .NET types embedded in the payload and can invoke arbitrary constructors, property setters, and `IDeserializationCallback`/`ISerializable` methods while doing so, which lets a crafted upload achieve remote code execution or object-injection attacks (denial of service, file writes, etc.) purely by being deserialized — no further application logic needs to run for the exploit to fire.

## Source

`[FromForm] IFormFile blob` (line 21), the multipart file upload posted to `POST api/[controller]/restore`, copied into `stream` (lines 23-25) and handed unmodified to `formatter.Deserialize(stream)` (line 29). The bytes are fully attacker-controlled and untrusted.

## Fix

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

            SessionState session;
            try
            {
                session = JsonSerializer.Deserialize<SessionState>(stream, new JsonSerializerOptions
                {
                    // Reject unrecognized members so an oversized or malformed payload
                    // cannot smuggle extra data through the cache.
                    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
                });
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

    // Plain-data contract for a restored session. Add only the fields the
    // client is expected to supply; System.Text.Json only ever populates
    // this concrete type, so it cannot be tricked into instantiating an
    // arbitrary .NET type the way BinaryFormatter could.
    public sealed class SessionState
    {
        public string? UserId { get; set; }
        public DateTimeOffset IssuedAt { get; set; }
    }
}
```

Replace `BinaryFormatter` with `System.Text.Json`'s `JsonSerializer.Deserialize<T>`, targeting a concrete, minimal DTO (`SessionState`) rather than `object`. This removes the taint sink entirely instead of trying to make `BinaryFormatter` safer: the JSON deserializer only ever populates the declared properties of the declared type, so a payload cannot direct it to construct or invoke members of an unrelated type. `UnmappedMemberHandling.Disallow` rejects payloads carrying fields outside the contract, and the `try/catch` turns a malformed upload into a `400` response instead of an unhandled exception. If the upstream client cannot be changed to send JSON, terminate the untrusted binary payload at the boundary (e.g. validate/parse it into known fields yourself) rather than feeding it to any general-purpose polymorphic deserializer — `BinaryFormatter`, `NetDataContractSerializer`, and `JavaScriptSerializer` with `SimpleTypeResolver` all share this same weakness and none of them should be reintroduced as a "quick fix" for the removed type.

## Explanation

`BinaryFormatter` is a polymorphic serializer: the byte stream itself specifies which .NET type to instantiate and which members to set, and .NET honors that instruction during `Deserialize` before any application code gets a chance to validate the result. An attacker who controls the upload can therefore point the payload at gadget types already loaded in the process (or in referenced assemblies) whose constructors, property setters, or deserialization callbacks have exploitable side effects — this is the standard .NET deserialization-gadget-chain technique and is independent of what the application intends `session` to be. Because the finding is that *any* trust of the byte stream's embedded type information is unsafe, the durable fix is to stop giving the caller that power at all: deserialize into a fixed, non-polymorphic DTO with a serializer (`System.Text.Json`, or `System.Xml.Serialization.XmlSerializer` for XML) that has no notion of "the stream names its own type." Microsoft's own guidance treats `BinaryFormatter` as unsafe to use with any untrusted input and has removed it from new .NET workloads (it throws `PlatformNotSupportedException` by default starting in .NET 9 for non-Windows-Forms/WPF app types); disabling that removal via `EnableUnsafeBinaryFormatterSerialization` to keep the old code path is not a remediation, it is opting back into the vulnerability. Caching the deserialized object afterward (`_cache.Set`) does not add any protection — the exploit already completes synchronously inside `Deserialize`, before the `Set` call is ever reached.
