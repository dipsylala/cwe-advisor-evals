## Verdict

Confirmed. The vulnerability is exploitable: untrusted user input from an HTTP POST body flows directly to `XmlDocument.LoadXml()` without any XXE protections. An attacker can inject DOCTYPE declarations with external entity references to read arbitrary files, perform SSRF, or cause denial of service.

## Source

HTTP POST parameter `xmlPayload` at controller method parameter `Upload([FromBody] string xmlPayload)` - user-supplied untrusted XML string.

## Fix

In the `Upload` method, set `XmlResolver = null` on the `XmlDocument` instance after creation but before calling `LoadXml()`:

```csharp
var doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external entity resolution
doc.LoadXml(xmlPayload);
```

## Explanation

`XmlDocument.LoadXml()` does not accept `XmlReaderSettings` as a parameter. When an `XmlDocument` is loaded directly (not through an `XmlReader`), it always uses its own `XmlResolver` to resolve external entities. Setting `doc.XmlResolver = null` disables external entity resolution entirely, blocking XXE injection. The document can still parse well-formed XML without external references, preserving legitimate functionality while closing the XXE attack surface.

## Behaviour changes

The fixed code rejects XML containing DOCTYPE declarations with external entity references, throwing an `XmlException`. This is the desired behaviour - XXE payloads are now detected and rejected at parse time rather than silently processed. Legitimate XML documents without external entities parse identically.

