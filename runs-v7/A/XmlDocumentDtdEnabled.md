## Verdict
CWE-611 is present. The `XmlDocument` loads untrusted XML without restricting DTD processing, enabling XXE attacks and external entity resolution.

## Source
Line 14: `doc.LoadXml(xmlPayload);`

The `xmlPayload` parameter originates from the request body and is parsed directly by `XmlDocument` without DTD restrictions.

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

        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        using (var reader = XmlReader.Create(new StringReader(xmlPayload), settings))
        {
            doc.Load(reader);
        }

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation
`XmlDocument.LoadXml()` does not accept `XmlReaderSettings`, so the fix loads through an `XmlReader` created with DTD restrictions. Set `DtdProcessing = DtdProcessing.Prohibit` to reject any DTD declarations and external entity references outright. Setting `XmlResolver = null` also prevents the parser from attempting to resolve external URIs. This dual approach ensures no external entities are processed and no network requests are made to resolve them.
