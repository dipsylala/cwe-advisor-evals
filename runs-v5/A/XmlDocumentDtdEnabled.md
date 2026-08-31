## Verdict

Confirmed. `XmlDocument.LoadXml` parses the request body as XML with DOCTYPE/DTD processing active and no `XmlResolver` restriction, so an attacker-supplied payload can declare a DOCTYPE with internal or external entities. This is CWE-611 (Improper Restriction of XML External Entity Reference).

## Source

`xmlPayload`, the `[FromBody] string` parameter of `ImportController.Upload`, is attacker-controlled HTTP request body content flowing directly into the parser with no schema restriction, size cap, or DOCTYPE screening.

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

`XmlDocument.LoadXml(string)` parses the supplied markup with an internal `XmlReader` whose `DtdProcessing` defaults to `Parse`, so a `<!DOCTYPE ...>` block in the payload is accepted and any entities it declares are expanded during parsing — this is what lets an attacker define an external entity that pulls in local file contents or reaches an internal/SSRF-reachable URL, or define nested internal entities that expand exponentially (a "billion laughs" denial of service). `LoadXml` gives the caller no way to override this behavior directly, so the fix routes parsing through an explicit `XmlReader` built from `XmlReaderSettings` and loads the document from that reader instead of from the raw string.

Two settings do the work together:

- `DtdProcessing = DtdProcessing.Prohibit` makes the reader throw an `XmlException` the moment it encounters a DOCTYPE declaration at all, rather than merely limiting what a DOCTYPE can do. Since this endpoint has no legitimate need for DTDs, rejecting them outright is the strongest and simplest defense — it removes both the external-entity and internal-entity-expansion attack surface in one setting.
- `XmlResolver = null` is kept as defense in depth. If `DtdProcessing` is ever relaxed to `Parse` or `Ignore` in a future edit, a null resolver still stops the reader from dereferencing external SYSTEM/PUBLIC identifiers, so external entities and external DTD subsets fail to resolve instead of being fetched.

`doc.Load(xmlReader)` is used in place of `doc.LoadXml(xmlPayload)` because `LoadXml` only accepts a raw string and always builds its own permissive reader internally — passing a pre-configured `XmlReader` is the only way to apply these restrictions while still populating an `XmlDocument` for the existing `SelectSingleNode` call. The rest of the method, including the XPath lookup and response shape, is unchanged.

Verify the fix with two tests: a payload containing `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><name>&xxe;</name>` should now cause the reader to throw on the DOCTYPE rather than return file contents in the response, and a normal payload with no DOCTYPE (e.g. `<root><name>value</name></root>`) should continue to parse and return `"value"` unchanged.
