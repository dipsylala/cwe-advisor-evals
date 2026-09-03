## Verdict

EXPLOITABLE. The `xmlPayload` parameter flows directly from untrusted HTTP input to `XmlDocument.LoadXml()` without disabling external entity resolution. Attacker-controlled XML containing DOCTYPE and SYSTEM entity declarations will be resolved by the parser, enabling file disclosure, SSRF, or denial of service.

## Source

`xmlPayload` parameter, string from HTTP request body (`[FromBody] string xmlPayload`), untrusted and attacker-controlled.

## Fix

Before calling `LoadXml()`, set `XmlResolver` to `null` to disable external entity resolution:

```csharp
var doc = new XmlDocument();
doc.XmlResolver = null;
doc.LoadXml(xmlPayload);
```

## Explanation

`XmlDocument.LoadXml()` loads XML without an intermediary `XmlReader`, so it uses the document's own `XmlResolver` property rather than reader settings. When loaded this way, `XmlDocument` retains a default resolver that resolves external entities even though other .NET APIs (`XmlReaderSettings.XmlResolver`) default to `null` in recent versions. Setting `XmlResolver = null` before parsing disables external entity resolution and prevents XXE attacks while preserving normal XML parsing for valid documents. The fix is minimal and does not alter the document's structure or the caller's subsequent consumption of parsed data.

## Behaviour changes

- External entity references in DOCTYPE declarations are now blocked and rejected during parsing
- Legitimate XML documents without entity references parse identically to before
- Malformed XML with entity references raises `XmlException` instead of disclosing files or reaching external hosts
- No change to the document structure or API contract for calling code
