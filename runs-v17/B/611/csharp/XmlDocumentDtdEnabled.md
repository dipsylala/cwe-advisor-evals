## Verdict

Confirmed vulnerability. `XmlDocument.LoadXml()` processes untrusted XML (`xmlPayload` from HTTP request body) without disabling external entity resolution. Setting `XmlResolver = null` before parsing closes the XXE vulnerability.

## Source

**File**: XmlDocumentDtdEnabled.cs  
**Line**: 14  
**Data flow**: `xmlPayload` (HTTP request body parameter, untrusted) → `XmlDocument.LoadXml(xmlPayload)` (sink)

The XML parser processes the untrusted payload without any XXE protections. `XmlDocument` does not have safe defaults for `XmlResolver` when loaded without an `XmlReader` - the document always uses its own resolver, enabling XXE attacks.

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
        doc.XmlResolver = null;  // Disable external entity resolution to prevent XXE

        doc.LoadXml(xmlPayload);

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation

The fix disables external entity resolution by setting `doc.XmlResolver = null` on the `XmlDocument` instance before calling `LoadXml()`. This prevents the XML parser from resolving external entities defined in DOCTYPE declarations or entity references, eliminating XXE attack vectors (file disclosure, SSRF, DoS). The parser will reject `<!DOCTYPE>` and external entity declarations. The fix is minimal and preserves the existing logic—legitimate XML documents without external entities parse normally.

## Behaviour changes

- XML documents containing `<!DOCTYPE>` declarations or external entity references are now rejected with an `XmlException` during parsing, where previously they would have been processed and entities resolved.
- Legitimate XML documents without external entities parse identically to before.
- No API changes; the same `XmlDocument` instance is used with identical downstream code (`SelectSingleNode`, `InnerText`).
