## Verdict

Real vulnerability. `XmlDocument.LoadXml()` processes untrusted XML without disabling external entity resolution, allowing XXE attacks to read arbitrary files, perform SSRF, or cause DoS.

## Source

User-supplied XML string passed via `[FromBody] string xmlPayload` at line 9, untrusted and attacker-controlled.

## Fix

Set `XmlResolver = null` on the `XmlDocument` instance before calling `LoadXml()` to disable external entity resolution:

```csharp
var doc = new XmlDocument();
doc.XmlResolver = null;
doc.LoadXml(xmlPayload);
```

## Explanation

`XmlDocument` does not inherit safe defaults for `XmlResolver` when loaded via `LoadXml()` — only when loaded through an `XmlReader` with secure settings. Setting `XmlResolver = null` explicitly blocks all external entity resolution, including DTD processing and file access. This prevents the parser from resolving external entities referenced in the XML, closing the XXE attack surface. The fix preserves the existing return value and caller contract; the document still parses correctly for legitimate XML that does not rely on external entities.

## Behaviour changes

Parser now rejects XML containing DOCTYPE declarations with external entity references or SYSTEM identifiers. Legitimate XML workflows that do not use external entities are unaffected. Applications using external DTDs for validation or entity expansion must move to schema validation (XSD) instead.
