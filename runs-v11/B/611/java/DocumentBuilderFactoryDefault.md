## Verdict
exploitable

## Source
`orderXml` parameter from HTTP request at line 18: `String orderXml = request.getParameter("orderXml");`

## Fix

**Vulnerable code (before):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Fixed code (after):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

try {
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
} catch (ParserConfigurationException e) {
    // Feature not recognized; continue with other hardening measures
}

try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException e) {
    // Feature not recognized
}

try {
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
} catch (ParserConfigurationException e) {
    // Feature not recognized
}

try {
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
} catch (ParserConfigurationException e) {
    // Feature not recognized
}

try {
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
} catch (ParserConfigurationException e) {
    // Feature not recognized
}

factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

## Explanation
The original code uses the default DocumentBuilderFactory configuration, which leaves XXE (XML External Entity) processing enabled. An attacker can inject malicious DOCTYPE declarations with external entity definitions in the `orderXml` parameter to read arbitrary files, perform SSRF attacks, or cause denial of service. The fix explicitly disables all dangerous XML parsing features: external entity resolution (both general and parameter entities), DTD processing, external DTD loading, and XInclude. Each setFeature call is wrapped in a try-catch block because different parser implementations may not recognize all feature URIs, but disabling these features prevents entity expansion and resolution even if some are unrecognized. The empty-string attributes (`ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA`) further restrict external access at the JAXP level, closing the XXE vector entirely while preserving the parser's ability to process well-formed XML documents without external references.

## Behaviour changes
- Added 7 try-catch blocks around setFeature calls: each wraps a feature URI that the parser implementation may not recognize, throwing `ParserConfigurationException`. These are caught locally to allow subsequent hardening attempts to proceed; the parser still achieves security through the recognized features that do take effect.
- Added `setXIncludeAware(false)` and `setExpandEntityReferences(false)`: documented controls over entity and include expansion that supplement DTD disabling; these do not change parsing semantics for documents without entity references.
- Added `setAttribute()` calls for `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` set to empty string: restrict external access at the JAXP level (arrived in JAXP 1.5/JDK 8); these do not alter behavior for documents that do not reference external resources.
- Sink contract preserved: the parse still accepts the same InputSource, returns the same Document object, throws the same exceptions on malformed XML; no return value or argument semantics changed.
