## Verdict

Exploitable. User-supplied XML from `request.getParameter("orderXml")` is parsed directly by a DocumentBuilderFactory configured with default settings, which enable DTD processing and external entity resolution. An attacker can inject XXE payloads to read arbitrary files, perform SSRF attacks, or cause denial of service.

## Source

Line 18: `String orderXml = request.getParameter("orderXml");` — untrusted HTTP parameter.

Data flows directly to the sink without validation or sanitization.

## Fix

**Vulnerable code (line 21-24):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Fixed code:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

try {
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
} catch (ParserConfigurationException e) {
    // Ignore if not supported on this parser
}

try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException e) {
    // Ignore if not supported on this parser
}

try {
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
} catch (ParserConfigurationException e) {
    // Ignore if not supported on this parser
}

try {
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
} catch (ParserConfigurationException e) {
    // Ignore if not supported on this parser
}

try {
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
} catch (ParserConfigurationException e) {
    // Ignore if not supported on this parser
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

The fix hardens the `DocumentBuilderFactory` before parsing by disabling all XXE attack vectors. It sets `FEATURE_SECURE_PROCESSING` to enable implementation-level protections, disables DOCTYPE declarations entirely (the primary control), disables external general and parameter entities, disables external DTD loading, disables XInclude, and sets the `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` attributes to the empty string to block all external access. Each `setFeature` call is wrapped in a try-catch to handle parsers that do not recognize the feature URI. These hardening steps must be applied to every parser factory instance before parsing untrusted XML, preventing the parser from resolving malicious entity references and closing the XXE vulnerability.

## Behaviour changes

The parser will now reject XML documents containing DOCTYPE declarations and external entity references. Where such documents were previously accepted, they will now be rejected or expanded to empty strings. The parse operation may throw `SAXException` if the XML contains DOCTYPE syntax. Applications relying on DTD-based features (rare) will need to redesign to handle XML without DOCTYPE. All other behavior remains unchanged: the returned `Document` object, exception handling, and downstream code patterns are preserved.
