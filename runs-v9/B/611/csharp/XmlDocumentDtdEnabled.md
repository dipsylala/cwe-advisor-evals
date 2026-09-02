## Verdict

exploitable (confidence: high)

## Source

`xmlPayload`, the `[FromBody] string` parameter of `ImportController.Upload` - raw, attacker-controlled HTTP request body content, passed with no validation or sanitization.

## Fix

Library recommendation: none - `System.Xml.XmlDocument` is a built-in BCL type; no third-party dependency is involved.

Vulnerable code:

```csharp
var doc = new XmlDocument();

// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
doc.LoadXml(xmlPayload);

var name = doc.SelectSingleNode("//name")?.InnerText;
```

Fixed code:

```csharp
var doc = new XmlDocument();
doc.XmlResolver = null;

doc.LoadXml(xmlPayload);

var name = doc.SelectSingleNode("//name")?.InnerText;
```

## Explanation

`XmlDocument.LoadXml(xmlPayload)` parses attacker-controlled XML directly. Unlike `XmlReader`, `XmlDocument` is not covered by the .NET-wide safe defaults (`DtdProcessing.Prohibit` since .NET Framework 4.0, null `XmlResolver` since 4.5.2): Microsoft documents that when a document is loaded other than through an `XmlReader`, `XmlDocument` always uses its own resolver, which by default is an `XmlUrlResolver` capable of fetching external resources. That leaves a DOCTYPE declaration in `xmlPayload` free to define an external or SYSTEM entity that the parser resolves - reading local files, issuing SSRF requests, or triggering entity-expansion DoS - with the result reachable through `SelectSingleNode`/`InnerText`. Setting `doc.XmlResolver = null` before `LoadXml` is the documented fix for this specific API: it removes the resolver `XmlDocument` would otherwise use to fetch external entities and the external subset of a DTD, so any such reference fails to resolve instead of being fetched, without altering how well-formed XML lacking external references is parsed.

## Behaviour changes

- Added `doc.XmlResolver = null` before parsing. This is the security fix itself (closes the XXE weakness) and is the only change from the original code.
- For XML payloads that declare a DOCTYPE with external or SYSTEM entities, those entities will no longer resolve (they expand to empty / are left unresolved) instead of fetching the referenced file or URL. This is the intended effect of the fix; any legitimate workflow that depended on external entity resolution in incoming XML would need to be re-evaluated, but none is evident in this handler.
- No change to the method's return value, control flow, or exception behavior for XML that does not reference external entities - `LoadXml` still throws `XmlException` on malformed XML, and `SelectSingleNode`/`InnerText` behavior is untouched.
