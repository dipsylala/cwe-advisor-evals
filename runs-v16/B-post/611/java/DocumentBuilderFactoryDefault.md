# CWE-611 Remediation: DocumentBuilderFactoryDefault.java

## Verdict

exploitable

## Source

Line 18: `String orderXml = request.getParameter("orderXml");` — untrusted XML content supplied by attacker through HTTP request parameter flows to the XML parser without validation or sanitization.

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

// Disable XXE attacks by restricting DTDs and external entity processing
try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
} catch (ParserConfigurationException e) {
    throw new RuntimeException("Failed to configure XML parser for XXE protection", e);
}

factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Required import:**

```java
import javax.xml.XMLConstants;
```

## Explanation

The original code creates a DocumentBuilderFactory with default settings, which leaves XXE attack vectors open: DOCTYPE declarations are accepted, external entities are resolved, and external DTDs are loaded. Untrusted XML from the request parameter flows directly to the parser. The fix applies comprehensive XXE protection by disabling all external entity and DTD processing features before creating the DocumentBuilder. Setting `disallow-doctype-decl` to true blocks DOCTYPE declarations entirely—this is the primary control for XXE prevention per the Java XML parsing guidance. The external entity features prevent both general and parameter entity resolution. The `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` properties are set to empty strings to block external protocol access. The `setFeature` calls are wrapped in try-catch because some XML parsers may not recognize all feature URIs. These hardening settings are applied to the factory before the builder is created and before parsing begins, ensuring consistent XXE protection across all parsing operations. When the parser encounters a DOCTYPE or external entity reference in the untrusted input, it will either reject the document or expand references to empty values, preventing file disclosure, Server-Side Request Forgery (SSRF), and denial-of-service attacks.

## Behaviour changes

- Parser will now reject or ignore DOCTYPE declarations and external entity references where they previously would have been processed. Applications that legitimately require DTD validation will need to reconsider their architecture; JSON is often a suitable alternative for simpler data formats.
- The `parse()` call behavior remains unchanged; it returns a Document object as before.
- Elements referencing external entities will be empty rather than populated with external content.
- Exception handling for parsing errors (ParserConfigurationException, SAXException) remains unchanged and still caught by the existing catch block.
- New inner try-catch wraps setFeature calls to convert ParserConfigurationException to RuntimeException, ensuring parser misconfiguration is explicitly caught rather than silently failing with vulnerable defaults.
- XMLConstants class is imported (javax.xml.XMLConstants), available in Java 5 and later.

## Verification

Compilation: javac run on the fixed code. Result: **successful** — all imports resolved, all methods and constants exist on DocumentBuilderFactory and XMLConstants classes, no syntax errors.

Test case compiled: `XXETestFixed.java` containing the core XXE protection pattern compiled successfully, confirming the fix is syntactically valid and uses only standard Java APIs.

## Assumptions

- Assumed attack surface is user-supplied XML in the request parameter, which is a common and realistic XXE vector.
- Assumed the application does not legitimately require DTD processing or external entity resolution; if it does, a more nuanced fix preserving controlled DTD access would be needed (the primary defence of disallow-doctype-decl would still apply, but with additional allowlist controls).
- All feature URIs and property constants (XMLConstants.FEATURE_SECURE_PROCESSING, XMLConstants.ACCESS_EXTERNAL_DTD, XMLConstants.ACCESS_EXTERNAL_SCHEMA) are verified as standard in Java 7u40+ and later, and are recognized by the reference implementation's DocumentBuilderFactory.
