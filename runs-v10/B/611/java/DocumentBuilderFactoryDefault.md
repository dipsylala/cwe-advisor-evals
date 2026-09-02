## Verdict

The finding is valid. The `DocumentBuilderFactory` is created with default settings that allow external entity resolution and DTD processing, making it vulnerable to XXE attacks. Untrusted XML from the HTTP request parameter flows directly to the parser without any security hardening.

## Source

Line 18: `String orderXml = request.getParameter("orderXml")` - untrusted user input from HTTP parameter

Line 24: `Document doc = builder.parse(new InputSource(new StringReader(orderXml)))` - sink where untrusted XML is parsed with insecure parser configuration

## Fix

**Import needed:**
```java
import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
```

**Original vulnerable code (lines 20-24):**
```java
try {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();
    // SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
    Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Fixed code:**
```java
try {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

    // Disable DTD and external entity processing to prevent XXE attacks
    try {
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setXIncludeAware(false);
        factory.setXIncludeAware(false);
    } catch (ParserConfigurationException e) {
        throw new RuntimeException("Failed to configure secure XML parser", e);
    }

    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

    DocumentBuilder builder = factory.newDocumentBuilder();
    Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

## Explanation

The fix hardens the `DocumentBuilderFactory` before parsing by explicitly disabling all XXE attack vectors: DTD declarations, external general entities, external parameter entities, external DTD loading, and XInclude. The `disallow-doctype-decl` feature is the primary control that blocks DOCTYPE declarations entirely. Additional features disable external entity resolution and secure processing is enabled. Both `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` attributes are set to empty strings to prevent external resource access at the JAXP level. These settings are wrapped in a try-catch block because some parser implementations may not recognize certain feature URIs and throw `ParserConfigurationException`. By applying these hardening steps before creating the `DocumentBuilder`, all parser instances use the secure configuration. The parse operation on line 24 (now later in the fixed sequence) now processes XML with external entity resolution disabled, preventing XXE injection.

## Behaviour changes

- **Parser behavior on DOCTYPE**: Documents containing `<!DOCTYPE` declarations will be rejected rather than processed
- **External entity references**: Any `<!ENTITY>` declarations referring to external resources will not be resolved; affected elements will be empty or missing rather than populated with external file contents
- **DTD processing**: Full DTD processing is disabled; only XML content is parsed
- **Error handling**: A `ParserConfigurationException` wrapped in a `RuntimeException` will be thrown if the parser does not support the security features (rare in modern JDK versions, but possible with alternative parser implementations)
- **No functional change for valid documents**: Documents without DOCTYPE or external entity references are processed identically to before
