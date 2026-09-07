## Verdict
Exploitable

## Source
`request.getParameter("orderXml")` at line 18 — untrusted user input passed to XML parser

## Fix

**Vulnerable Code (lines 21-24):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Fixed Code:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable DTDs and external entities to prevent XXE attacks
try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException e) {
    // Feature not recognized, continue with other settings
}
try {
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
} catch (ParserConfigurationException e) {
    // Feature not recognized, continue with other settings
}
try {
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
} catch (ParserConfigurationException e) {
    // Feature not recognized, continue with other settings
}
try {
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
} catch (ParserConfigurationException e) {
    // Feature not recognized, continue with other settings
}
try {
    factory.setFeature("http://java.sun.com/xml/features/disallow-doctype-decl", true);
} catch (ParserConfigurationException e) {
    // Feature not recognized, continue with other settings
}

factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

// Disable external DTD and schema access (JAXP 1.5+, JDK 7u40+)
try {
    factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
} catch (IllegalArgumentException e) {
    // Property not supported, continue with other settings
}
try {
    factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
} catch (IllegalArgumentException e) {
    // Property not supported, continue with other settings
}

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

## Explanation

The DocumentBuilderFactory is created with default settings that allow XXE attacks. By default, Java's XML parsers resolve external entities defined in Document Type Declarations, allowing attackers to inject malicious XML that reads arbitrary files, performs SSRF attacks, or causes denial of service. The fix hardens the factory by: (1) disabling DOCTYPE declarations entirely with the `disallow-doctype-decl` feature; (2) disabling external general and parameter entity processing; (3) disabling external DTD loading; (4) disabling XInclude expansion; and (5) restricting external DTD and schema access via properties. Each `setFeature()` and `setAttribute()` call is wrapped with exception handling because different XML parser implementations may not recognize all features, and the fix must not introduce new failures. These settings must be applied to the factory before any parser instances are created from it.

## Behaviour changes

The parse method's return value and exception contract remain unchanged — the method still returns a parsed Document or throws ParserConfigurationException/SAXException as before. External entity references in the XML will now be rejected or expand to empty content rather than being resolved, which may cause the parse to succeed with missing data if a handler treats absent values as optional (as the current code does by calling `item(0).getTextContent()` without null checking). This is the intended hardening: silently processing an XXE-injected document with empty fields is preferable to silently exfiltrating data or achieving remote code execution.
