## Verdict

Confirmed. `XmlDocument.LoadXml` is called on attacker-controlled input (`xmlPayload`, the raw JSON-bound request body) without disabling external entity resolution, allowing an XML External Entity (XXE) attack.

## Source

`xmlPayload`, the `[FromBody] string` parameter of `ImportController.Upload`, is untrusted input taken directly from the HTTP request body and passed unmodified into `XmlDocument.LoadXml`.

## Fix

### File: XmlDocumentDtdEnabled.cs

```csharp
using System.Xml;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ImportController : ControllerBase
{
    [HttpPost("upload")]
    public IActionResult Upload([FromBody] string xmlPayload)
    {
        var doc = new XmlDocument();
        doc.XmlResolver = null;

        doc.LoadXml(xmlPayload);

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation

`XmlDocument.LoadXml` parses a DTD if the input declares one, and any `SYSTEM`/`PUBLIC` external entity or external DTD subset it references is fetched through the document's `XmlResolver`. An attacker who controls `xmlPayload` can declare an entity such as `<!ENTITY xxe SYSTEM "file:///etc/passwd">` (or an `http://` URL to reach internal services/SSRF) and reference it in the `<name>` element, so its resolved content is read back through `SelectSingleNode("//name")?.InnerText` and returned to the caller in the response body - both local file disclosure and internal network access.

The fix sets `doc.XmlResolver = null` before calling `LoadXml`. `XmlResolver` is the component `XmlDocument` uses to resolve any external reference found during parsing; with it null, the parser can no longer dereference external entities or external DTD subsets, so any such reference in the payload resolves to nothing instead of fetching attacker-chosen content. This is a one-line, behavior-preserving change: it does not alter how well-formed XML without external references is parsed, and `SelectSingleNode`/`InnerText` continue to work exactly as before for legitimate payloads. Setting the resolver explicitly (rather than relying on a runtime's default) makes the fix correct regardless of which .NET target the application runs on, and keeps the code safe if it is ever ported to a runtime whose default resolver is non-null.
