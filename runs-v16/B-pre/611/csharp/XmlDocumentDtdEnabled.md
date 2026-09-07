## Verdict

CWE-611 confirmed. Untrusted XML input is parsed by `XmlDocument.LoadXml()` without disabling external entity resolution. The `XmlResolver` property is not explicitly set to `null`, so the parser will attempt to resolve `<!DOCTYPE>` declarations and external entity references, enabling XXE attacks.

## Source

**File:** evals/cases/611/csharp/XmlDocumentDtdEnabled/XmlDocumentDtdEnabled.cs
**Line:** 14
**Sink:** `doc.LoadXml(xmlPayload)`

**Data Flow:**
- **Source:** `xmlPayload` parameter, string from HTTP POST body (`[FromBody]` attribute)
- **Attacker Control:** Yes - direct HTTP request body
- **Flow:** Attacker-controlled XML string → `LoadXml()` → unprotected parser

## Fix

**Vulnerable Code (lines 10-14):**
```csharp
var doc = new XmlDocument();

// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
doc.LoadXml(xmlPayload);
```

**Fixed Code:**
```csharp
var doc = new XmlDocument();
doc.XmlResolver = null;  // Disable external entity resolution

doc.LoadXml(xmlPayload);
```

## Explanation

`XmlDocument.LoadXml()` is the primary XXE sink in C#. When called without hardening, the document's `XmlResolver` property defaults to an instance that resolves external entities from system resources, allowing attackers to inject `<!DOCTYPE>` declarations with `SYSTEM` or `PUBLIC` entities to read files, trigger SSRF attacks, or cause denial of service.

Setting `doc.XmlResolver = null` before parsing explicitly disables external entity resolution for this document instance. Unlike other .NET XML parsers (`XmlReaderSettings.DtdProcessing` defaults to `Prohibit` since .NET Framework 4.0), `XmlDocument` retains its own resolver and does not inherit settings from an `XmlReader` after loading, so the property assignment is the primary defence for this API.

The fix is minimal, surgical, and preserves the existing return contract: `LoadXml()` still returns void, still parses the XML structure into the document, and still throws on malformed input.

## Behaviour changes

- **Parser rejection of external entities:** The parser now rejects any attempt to resolve external entities defined in DOCTYPE declarations. Malicious payloads containing `<!DOCTYPE name [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` will be rejected.
- **Rejection of file access attempts:** SSRF and file-disclosure attacks via entity references are blocked.
- **Legitimate XML processing unaffected:** Valid XML without external entity references continues to parse and load normally. The document structure, element selection, and `SelectSingleNode()` calls work identically.
- **Error handling unchanged:** Parse errors still throw `XmlException` as before.
