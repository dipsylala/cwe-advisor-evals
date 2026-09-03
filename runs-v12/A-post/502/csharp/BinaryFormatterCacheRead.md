## Verdict
CWE-502 confirmed. The code deserializes untrusted user input using `BinaryFormatter.Deserialize()`, which is inherently unsafe and can execute arbitrary code through crafted payloads.

## Source
`BinaryFormatter` has been deprecated by Microsoft since .NET Framework 4.8 and .NET Core 3.1 due to fundamental security issues. The vulnerability occurs because `BinaryFormatter` can instantiate and invoke methods on arbitrary .NET types during deserialization, allowing remote code execution if an attacker controls the serialized data. In this case, the blob data comes directly from a user file upload with no validation.

## Fix
Replace `BinaryFormatter` with a safer serialization approach. For session data in ASP.NET Core, use `System.Text.Json` or `Newtonsoft.Json`:

```csharp
[HttpPost("restore")]
public IActionResult RestoreSession([FromForm] IFormFile blob)
{
    using var reader = new StreamReader(blob.OpenReadStream());
    var json = reader.ReadToEnd();
    
    // Deserialize using System.Text.Json with a known type
    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
    var session = JsonSerializer.Deserialize<SessionData>(json, options);
    
    if (session == null)
    {
        return BadRequest("Invalid session data");
    }
    
    _cache.Set("session", session);
    return Ok();
}
```

Ensure the deserialization target is a concrete type you control, not `object`. Add input validation: validate the blob size before reading, check content type is `application/json`, and validate deserialized content meets expected constraints.

## Explanation
`BinaryFormatter` deserializes using reflection and can instantiate arbitrary types, including those with malicious constructor side effects or property setters. An attacker-controlled file can exploit gadget chains to execute code during deserialization. JSON deserialization with an explicit, concrete type is safer because it only instantiates that specific type and validates structure. The fix requires the blob to conform to the schema of `SessionData`, rejecting anything else. Add file size limits in the controller or middleware to prevent denial of service.
