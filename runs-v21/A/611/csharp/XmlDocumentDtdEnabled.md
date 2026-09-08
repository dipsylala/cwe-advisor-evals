## Verdict

Confirmed: CWE-611 vulnerability in XmlDocument.LoadXml() without DTD processing restrictions. User-supplied XML is parsed without disabling external entity processing, allowing XXE attacks.

## Source

XmlDocument instantiation at line 11, LoadXml call at line 14 with unsanitized `xmlPayload` parameter from HTTP request body.

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

        // Disable DTD processing to prevent XXE attacks
        doc.XmlResolver = null;

        doc.LoadXml(xmlPayload);

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation

The fix sets `XmlResolver` to `null` on the XmlDocument instance before calling `LoadXml()`. This disables the external entity resolver, preventing the parser from attempting to resolve or load external DTD declarations or entity references, which is the mechanism XXE exploits use. Setting `XmlResolver = null` is the standard C# mitigation for XmlDocument without requiring additional dependencies or API changes.

