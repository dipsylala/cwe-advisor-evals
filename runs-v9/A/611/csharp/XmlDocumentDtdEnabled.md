## Verdict

Confirmed. `XmlDocument.LoadXml(string)` gives the caller no control over DTD processing: it always parses any DOCTYPE declaration present in the input and expands internal entities. An attacker-supplied payload containing a `<!DOCTYPE ... [ <!ENTITY xxe SYSTEM "..."> ]>` block, or nested entity definitions (entity-expansion / "billion laughs"), is parsed and expanded before the resulting DOM is queried, so untrusted XML reaches a DTD-processing parser with no restriction in place at the point of parsing.

## Source

`xmlPayload`, the `[FromBody] string` parameter of `ImportController.Upload`, is attacker-controlled request body content with no validation or filtering applied before being handed to the parser.

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

        var safeSettings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };

        using (var stringReader = new StringReader(xmlPayload))
        using (var xmlReader = XmlReader.Create(stringReader, safeSettings))
        {
            doc.Load(xmlReader);
        }

        var name = doc.SelectSingleNode("//name")?.InnerText;
        return Ok(name);
    }
}
```

(Add `using System.IO;` alongside the existing usings.)

## Explanation

`XmlDocument.LoadXml(string)` has no overload that accepts `XmlReaderSettings`, so it cannot be configured directly - the only way to control DTD behavior for `XmlDocument` is to parse through an `XmlReader` built from explicit `XmlReaderSettings` and load the document from that reader instead of from the raw string.

Two settings matter, and both are needed:

- `DtdProcessing = DtdProcessing.Prohibit` makes the reader throw an `XmlException` as soon as it encounters a `DOCTYPE` declaration at all, closing off both external entity resolution and internal-entity-expansion (billion laughs) denial-of-service, rather than only the external-fetch path.
- `XmlResolver = null` is defense in depth: it removes the parser's ability to resolve any external URI (system identifiers, external DTD subsets) even if DTD processing were ever re-enabled elsewhere in the call chain, so a future change to the reader settings does not silently reopen the external-entity channel.

Setting only `XmlResolver = null` while leaving DTD processing enabled is not sufficient on its own - internal entity definitions and DOCTYPE parsing still occur without any network fetch, which still allows entity-expansion denial-of-service and is unnecessary parsing of untrusted structure. Prohibiting DTD processing outright is correct here because the endpoint's contract only needs a `//name` element value - there is no legitimate use case for the payload declaring a DTD at all.

After the change, `doc.SelectSingleNode("//name")?.InnerText` continues to work unchanged for well-formed XML without a DOCTYPE, so normal, expected payloads are unaffected. Verify by sending a payload containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><name>&xxe;</name></root>` and confirming the request now fails with an `XmlException` from `DtdProcessing.Prohibit` instead of returning file contents or expanded entity text.
