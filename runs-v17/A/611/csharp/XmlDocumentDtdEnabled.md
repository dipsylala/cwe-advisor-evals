## Verdict
Confirmed XXE vulnerability. `XmlDocument.LoadXml()` processes external entities without restriction.

## Source
User-supplied `xmlPayload` parameter passed directly to `XmlDocument.LoadXml()` at line 14.

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

        // Disable DTD processing and external entity resolution
        doc.XmlResolver = null;

        doc.LoadXml(xmlPayload);

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation
Setting `XmlDocument.XmlResolver = null` prevents the XML parser from resolving external entity references and DTD declarations. This blocks XXE attacks by making external entity expansion impossible. The XML document can still be parsed for its structure and content, but any attempt to reference external resources will fail safely.
