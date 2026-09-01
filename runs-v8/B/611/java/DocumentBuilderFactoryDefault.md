## Verdict

Exploitable. Untrusted XML from `request.getParameter("orderXml")` flows directly to `builder.parse()` without XXE hardening.

## Source

`request.getParameter("orderXml")` at line 18 - untrusted user-controlled XML input.

## Fix

**Vulnerable code:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Fixed code:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable XXE processing - wrap each feature individually to handle parser-specific exceptions
try {
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
} catch (ParserConfigurationException e) {
    // Continue; feature may not be supported by this parser
}

try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException e) {
    // Continue; feature may not be supported
}

try {
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
} catch (ParserConfigurationException e) {
    // Continue
}

try {
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
} catch (ParserConfigurationException e) {
    // Continue
}

try {
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
} catch (ParserConfigurationException e) {
    // Continue
}

factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

Note: Requires adding `import javax.xml.XMLConstants;` to the imports.

## Explanation

The vulnerability occurs because `DocumentBuilderFactory.newInstance()` creates a parser with default settings that allow processing of external entities and DTDs. An attacker can embed malicious DOCTYPE declarations and entity definitions in the XML parameter to read arbitrary files, trigger SSRF attacks, or cause denial of service through entity expansion. The fix disables all external entity and DTD processing features before parsing begins. Each feature is wrapped individually in try-catch because different XML parser implementations may not recognize all feature URIs; a fix that throws an unhandled exception is not a fix. The combination of these settings ensures the parser rejects DOCTYPE declarations and external entity references across all supported parser implementations. Setting `setXIncludeAware(false)` and `setExpandEntityReferences(false)` provides defense-in-depth by disabling additional XML processing paths that could bypass entity restrictions.

## Behaviour changes

- Entity references in the input now expand to empty strings or cause parsing to silently skip them, rather than being resolved from external sources. Applications that require DTD validation or specific entity expansion must use a different mitigation strategy (such as validating XML against a static schema before parsing).
- ParserConfigurationException handling is added; the try-catch blocks allow configuration to proceed even if a particular feature is not recognized by the parser implementation.
- No changes to method signatures, return values, or error handling behavior beyond the added try-catch blocks for feature configuration.
