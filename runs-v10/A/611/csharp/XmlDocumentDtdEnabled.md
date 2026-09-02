## Verdict
The vulnerability is confirmed. `XmlDocument.LoadXml()` with default settings allows DTD processing and external entity resolution, enabling XXE attacks.

## Source
Untrusted XML input received via `xmlPayload` parameter on line 9, sourced from user request body.

## Fix
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
Set `XmlResolver` to `null` before calling `LoadXml()` to prevent the XML parser from resolving external entities defined in DOCTYPE declarations. This blocks XXE attacks where an attacker provides malicious external entity references in the XML payload. The `XmlResolver` property controls whether external entities and schemas are resolved; setting it to `null` disables this functionality while allowing normal XML parsing to continue.
