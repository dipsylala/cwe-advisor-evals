## Verdict

Vulnerability confirmed and remediable. XXE injection via unsecured `XmlDocument.LoadXml()` parsing user-controlled XML without DTD or external entity restrictions.

## Source

File: `XmlDocumentDtdEnabled.cs`, line 14
- **Source**: `xmlPayload` parameter from HTTP POST request body (untrusted user input)
- **Sink**: `doc.LoadXml(xmlPayload)` - XmlDocument parses the string without security hardening
- **Issue**: Default `XmlDocument` behavior allows DTD processing and external entity resolution, enabling XXE attacks (file disclosure, SSRF, DoS)

Data flow: User POST request → `xmlPayload` string parameter → `LoadXml()` → XML parser processes entities

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
        var settings = new XmlReaderSettings 
        { 
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        var doc = new XmlDocument();
        doc.XmlResolver = null;
        
        using (var reader = XmlReader.Create(new System.IO.StringReader(xmlPayload), settings))
        {
            doc.Load(reader);
        }

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation

The fix hardens XML parsing in three layers:

1. **`XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit`**: Rejects all DOCTYPE declarations and DTD processing, blocking external entity definitions at parse time.

2. **`XmlReaderSettings.XmlResolver = null`**: Disables external entity resolution in the reader, preventing file access or network requests through SYSTEM/PUBLIC entity declarations.

3. **`doc.XmlResolver = null`**: Explicitly sets the XmlDocument's resolver to null. This is necessary because when a document is loaded without an XmlReader, it always uses its own resolver (not inherited from the reader after Load completes). This ensures no entity resolution happens even if the loaded XML somehow bypasses the reader's DTD prohibition.

4. **`XmlReader.Create()` wrapper**: Parses the XML through the secure reader (rather than direct `LoadXml()`), ensuring the prohibitive settings are enforced during document construction.

The fix preserves the original functionality: the XML is parsed, a node is selected by XPath, and the inner text is returned. No legitimate XML features are lost for the typical use case.

## Behaviour changes

No behaviour change for valid XML input. The fix:
- Rejects any XML containing DOCTYPE declarations (previously accepted)
- Rejects any XML with external entity references via SYSTEM/PUBLIC (previously resolved)
- Returns the same extracted value (`name` element inner text) for well-formed XML without malicious DTDs
- Throws `XmlException` during parsing if a DOCTYPE is encountered, instead of silently processing it

The application will reject malformed XXE payloads at the parser stage, failing fast with a clear error rather than silently exposing internal resources.
