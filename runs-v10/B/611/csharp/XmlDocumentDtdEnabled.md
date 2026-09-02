## Verdict
exploitable

## Source
`xmlPayload` parameter (untrusted user input from ASP.NET `[FromBody]` binding)

## Fix

**Vulnerable code:**
```csharp
var doc = new XmlDocument();

// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
doc.LoadXml(xmlPayload);
```

**Fixed code:**
```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};

var doc = new XmlDocument();
using (var reader = XmlReader.Create(new StringReader(xmlPayload), settings))
{
    doc.Load(reader);
}
```

## Explanation
The original code calls `XmlDocument.LoadXml()` with untrusted user input without disabling external entity processing. Attackers can inject DOCTYPE declarations or ENTITY definitions to read arbitrary files, perform SSRF attacks, or cause denial-of-service. The fixed code wraps the untrusted XML string in a `StringReader` and loads it through an `XmlReader` configured with `DtdProcessing = DtdProcessing.Prohibit` to reject DOCTYPE declarations and `XmlResolver = null` to block external entity resolution. This ensures external entities are completely disabled before parsing begins, eliminating the XXE attack surface.

## Behaviour changes
The functional behavior remains the same. Both `LoadXml()` and `Load()` through `XmlReader` parse the XML string and populate the `XmlDocument` identically; subsequent calls to `SelectSingleNode()` and property access return the same results. The changes are security-focused: applying DTD and external entity restrictions via `XmlReaderSettings` before parsing, with no impact on the document structure, return value, or error handling contract.
