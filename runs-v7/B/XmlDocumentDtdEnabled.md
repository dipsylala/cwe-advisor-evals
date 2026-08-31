## Verdict

Exploitable. The vulnerable code passes user-controlled XML from an HTTP request body directly to `XmlDocument.LoadXml()` without configuring the parser to block external entities. `XmlDocument` does not set safe defaults for `XmlResolver` when loading XML through `LoadXml()` (as opposed to through an `XmlReader`), so external entities and DTDs are processed by default. An attacker can inject a malicious DOCTYPE with external entity references to read arbitrary files, perform Server-Side Request Forgery (SSRF) attacks, or cause Denial of Service (DoS).

## Source

`xmlPayload` parameter from `[FromBody]` attribute in the `Upload` method. This is user-controlled XML input from the HTTP request body, with no validation or sanitization before parsing.

## Fix

**Vulnerable code (line 14):**
```csharp
var doc = new XmlDocument();

// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
doc.LoadXml(xmlPayload);
```

**Fixed code:**
```csharp
var doc = new XmlDocument();

// Block external entity resolution to prevent XXE attacks
doc.XmlResolver = null;

doc.LoadXml(xmlPayload);
```

## Explanation

`XmlDocument` requires explicit hardening against XXE attacks. Unlike `XmlReader` or newer APIs, `XmlDocument` does not enforce safe defaults for `XmlResolver` when loading XML through `LoadXml()`. Setting `XmlResolver = null` before calling `LoadXml()` disables all external entity resolution and DTD processing, preventing the parser from accessing external files or making outbound requests. This eliminates XXE injection attacks while preserving normal XML parsing for legitimate, self-contained XML documents.

## Behaviour changes

None. Setting `XmlResolver = null` only blocks external entity and DTD processing. All legitimate XML parsing operations continue to work: element selection, XPath queries (`SelectSingleNode()`), InnerText extraction, and parsing of well-formed XML documents without external references. The fix does not alter return values, arguments, or output.
