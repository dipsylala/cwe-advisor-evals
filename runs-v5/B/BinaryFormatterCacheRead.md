## Verdict

- **cwe_id**: CWE-502 (Deserialization of Untrusted Data)
- **location**: `BinaryFormatterCacheRead.cs`, line 29 (`formatter.Deserialize(stream)`), inside `SessionCacheController.RestoreSession`
- **verdict**: exploitable
- **confidence**: high
- **assumptions**: the case file has no accompanying `.csproj`, so the target framework cannot be confirmed. `BinaryFormatter.Deserialize` is only a hard runtime failure on .NET 9+ with its compatibility switches removed; this trace assumes an earlier .NET (Core/5-8) or .NET Framework target, where the call executes and is fully exploitable. The concrete type produced by deserialization (referred to below as `SessionData`) is not defined in the single-file case, so the fix names a placeholder type standing in for whatever session-state class the real application uses.

## Source

- **Source**: `blob`, an `IFormFile` bound from `[FromForm]` on the public `POST api/session/restore` endpoint. No `[Authorize]` attribute is present and no content-type, size, or structural validation is applied to the upload before use.
- **Path**: `blob.CopyTo(stream)` copies the raw upload bytes verbatim into a `MemoryStream`; `stream.Position` is reset to 0; the stream is then passed unmodified to `new BinaryFormatter().Deserialize(stream)`.
- **Sink**: `BinaryFormatter.Deserialize(Stream)` at line 29. `BinaryFormatter` reads type information from the stream itself and instantiates whatever type the payload names, running arbitrary constructors/callbacks during graph reconstruction. There is no signature/HMAC check, no type allowlist, and no try/catch around the call.
- **Sink contract**: returns `object`, stored in `_cache.Set("session", session)` and the request answered with `200 OK`; nothing is discarded. Any deserialization failure throws (`SerializationException` or similar) uncaught, which ASP.NET Core turns into a `500` response — there is no existing custom error path to preserve.

Nothing between source and sink constrains or validates the payload, so the finding is exploitable as reported: an attacker who controls the multipart upload controls the type(s) instantiated by `BinaryFormatter`, which Microsoft states cannot be made safe by any configuration.

## Fix

**Library recommendation**: replace `BinaryFormatter` with `System.Text.Json`, which is part of the runtime's shared framework (no NuGet package or version pin needed on .NET Core/5+; for .NET Framework targets, add the `System.Text.Json` NuGet package and confirm the resolved version against SCA/dependency-check tooling before merging). This is a format replacement, not a version bump — the knowledge base guidance and Microsoft's own documentation state `BinaryFormatter` has no safe configuration at any version, so upgrading it is not an option.

**Vulnerable code**:
```csharp
using var stream = new MemoryStream();
blob.CopyTo(stream);
stream.Position = 0;

var formatter = new BinaryFormatter();
// SAST FINDING: CWE-502 (Deserialization of Untrusted Data) reported here. Sink is the next statement.
var session = formatter.Deserialize(stream);

_cache.Set("session", session);
return Ok();
```

**Fixed code**:
```csharp
using var stream = new MemoryStream();
blob.CopyTo(stream);
stream.Position = 0;

// System.Text.Json only populates members of the declared target type and never
// resolves a type from the payload itself, so the attacker can no longer choose
// what gets constructed.
var session = JsonSerializer.Deserialize<SessionData>(stream);
if (session is null)
{
    return BadRequest();
}

_cache.Set("session", session);
return Ok();
```

(with `using System.Text.Json;` added in place of `using System.Runtime.Serialization.Formatters.Binary;`, and `SessionData` a concrete, compile-time-fixed class matching the application's real session-state shape — it must be a plain data type with no logic that would be dangerous to have its properties set by untrusted input.)

## Explanation

The vulnerability is that `BinaryFormatter.Deserialize` lets the uploaded stream dictate which .NET type(s) get instantiated and which constructors/deserialization callbacks run, so an attacker-crafted upload can achieve remote code execution with no authentication required. Swapping in `JsonSerializer.Deserialize<SessionData>` removes that control entirely: `System.Text.Json` only ever constructs the one type named at the call site (`SessionData`), fixed at compile time, and populates its declared members from JSON — it cannot be steered into instantiating an attacker-chosen type or invoking arbitrary code paths during construction. This is the type-whitelisting defence from the loaded guidance applied directly: the "whitelist" here is the single concrete type baked into the generic parameter, which is stronger than an enumerated allowlist since no other type is even reachable through this call.

## Behaviour changes

- **Upload content format**: the endpoint now expects the uploaded file to contain UTF-8 JSON matching `SessionData` instead of a .NET binary-serialization stream. This is a wire-format break for any legitimate caller, but it is unavoidable — `BinaryFormatter` has no safe configuration to fall back to, and the knowledge base guidance and Microsoft both direct replacing the format, not hardening it in place.
- **Added null check / `BadRequest()` on null**: `JsonSerializer.Deserialize<T>` returns `null` for a JSON literal `null` payload, whereas `BinaryFormatter.Deserialize` never returned `null` on valid input (it throws instead on anything it can't reconstruct). The added check prevents silently caching a `null` session under the `"session"` key, which the original code's success path could never have produced.
- **Unhandled deserialization failure**: preserved as-is. `JsonSerializer.Deserialize` throws `JsonException` on malformed input, uncaught, just as `BinaryFormatter.Deserialize` threw uncaught on the original path — both surface as an ASP.NET Core `500` response, so this failure behaviour is unchanged.
- **`SessionData` type introduced**: not present in the original single-file case. The real fix must point this at the application's actual session-state type rather than the placeholder used here; this is called out under Assumptions above rather than treated as a safe default.
