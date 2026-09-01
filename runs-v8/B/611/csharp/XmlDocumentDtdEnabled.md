## Verdict

Exploitable. Untrusted XML from the HTTP request body is parsed by XmlDocument without XXE protections, allowing an attacker to inject external entity references to read arbitrary files, perform SSRF attacks, or cause denial of service.

## Source

`xmlPayload` parameter from `[FromBody] string xmlPayload` (line 9) - attacker-controlled HTTP request body.

## Fix

**Vulnerable code:**
```csharp
var doc = new XmlDocument();

// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
doc.LoadXml(xmlPayload);
```

**Fixed code:**
```csharp
var doc = new XmlDocument();

// Disable external entity resolution to prevent XXE attacks
doc.XmlResolver = null;

doc.LoadXml(xmlPayload);
```

## Explanation

Setting `XmlResolver = null` on the XmlDocument instance disables external entity resolution before parsing begins. XmlDocument does not inherit the safe defaults from XmlReaderSettings (which has prohibited DTD processing since .NET Framework 4.0); instead, it always uses its own resolver when loaded directly without an XmlReader. By nullifying the resolver, the parser cannot resolve external entity declarations in the DOCTYPE, blocking XXE attack vectors including file disclosure (via `file://` URIs), SSRF attacks (via HTTP/HTTPS URIs to internal services), billion-laughs DoS attacks, and external DTD loading.

## Behaviour changes

None. LoadXml continues to accept and parse the XML string as before. The only change is that external entity references are now rejected rather than resolved. Legitimate XML workflows that do not rely on external entities are unaffected. XML with entity references will now fail to parse with an XmlException, which is the correct security-first behaviour for untrusted input.
