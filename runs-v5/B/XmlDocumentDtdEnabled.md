## Verdict

exploitable (confidence: high)

- CWE-611, Improper Restriction of XML External Entity Reference
- Location: `XmlDocumentDtdEnabled.cs`, line 14, `doc.LoadXml(xmlPayload)`

## Source

`xmlPayload`, the `[FromBody] string` parameter of `ImportController.Upload`. It is the raw HTTP request body for `POST api/import/upload`, fully attacker-controlled, and reaches the sink with no validation, filtering, or transformation between the method entry and line 14.

## Fix

Vulnerable code:

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

        // SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
        doc.LoadXml(xmlPayload);

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

Fixed code:

```csharp
using System.IO;
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

        var readerSettings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        using (var stringReader = new StringReader(xmlPayload))
        using (var xmlReader = XmlReader.Create(stringReader, readerSettings))
        {
            doc.Load(xmlReader);
        }

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

## Explanation

`XmlDocument` is the one .NET XML API whose `XmlResolver` is not null by default: per Microsoft's own documentation, when a document is loaded other than through an `XmlReader`, `XmlDocument` always uses its own (non-null) resolver, so `doc.LoadXml(xmlPayload)` resolves any `SYSTEM`/`PUBLIC` external entity declared in the payload's DTD - allowing local file disclosure and SSRF via a crafted `<!DOCTYPE>`. The fix applies both layers the C# guidance calls for: the parse path is routed through an `XmlReader` configured with `DtdProcessing = DtdProcessing.Prohibit` (rejects any `<!DOCTYPE` outright, the strongest available option) and `XmlResolver = null` (belt-and-suspenders against entity resolution), and `doc.XmlResolver` is set to `null` explicitly on the `XmlDocument` instance itself, since a resolver configured only on the reader is not retained by the document once `Load` returns and any resolver-driven behaviour after load (e.g. schema resolution) would otherwise still use the document's own default resolver. `doc.SelectSingleNode("//name")` is unaffected - it operates on the in-memory DOM built from the (now DTD-free) document.

## Behaviour changes

- The parse now throws `System.Xml.XmlException` if the payload contains a `<!DOCTYPE` declaration at all, including a benign one with no external entity reference - the original `LoadXml` accepted such documents. This is intentional (rejecting `<!DOCTYPE` outright is the strongest, guidance-recommended option) but is a behavioural narrowing callers should be aware of if any legitimate client currently sends XML with an internal-only DTD.
- No other differences: the method still returns `Ok(name)` from the same XPath query, on the same `IActionResult` contract, with no new success-path output and no arguments substituted for previously-implicit ones.
