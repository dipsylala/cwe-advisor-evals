## Verdict

Exploitable. Untrusted user input (`orderXml` from `HttpServletRequest.getParameter()` on line 18) flows to `DocumentBuilder.parse()` on line 24 without any XXE hardening. The `DocumentBuilderFactory` uses default configuration, which enables external entity resolution and DTD processing by default, allowing attackers to supply XML containing external entity declarations for file disclosure, SSRF, or denial of service.

## Source

User-supplied XML string: `String orderXml = request.getParameter("orderXml")` (line 18)

## Fix

**Vulnerable code (lines 21-24):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

**Fixed code:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable DTDs and external entity processing to prevent XXE attacks
try {
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setXIncludeAware(false);
} catch (ParserConfigurationException e) {
    throw new RuntimeException("Failed to configure secure XML parser", e);
}

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

## Explanation

The fix applies five hardening features to the `DocumentBuilderFactory` before creating the parser and parsing input. This closes XXE attack vectors by:

1. **Disallowing DOCTYPE declarations entirely** (`disallow-doctype-decl` = true) - this is the primary control that prevents DTD-based attacks, as the Javadoc for `FEATURE_SECURE_PROCESSING` only addresses "implementation limits" like entity expansion, not entity resolution.

2. **Disabling external general entities** (external-general-entities = false) - prevents entity references that attempt to fetch external resources.

3. **Disabling external parameter entities** (external-parameter-entities = false) - blocks parameter entity injection in DTDs.

4. **Disabling external DTD loading** (load-external-dtd = false) - prevents the parser from retrieving DTDs from network locations.

5. **Disabling XInclude** (setXIncludeAware = false) - blocks XML inclusions that could reference external resources.

Each `setFeature` call is wrapped in a try-catch for `ParserConfigurationException` because some parser implementations may not recognize all feature URIs, and a fix that throws on certain JVMs is not usable. The exception is re-thrown as a `RuntimeException` to fail fast if secure parser configuration cannot be established, preventing insecure parsing from silently proceeding.

## Behaviour changes

**Added exception handling:** A `ParserConfigurationException` from any of the feature-setting calls will now cause the method to throw a `RuntimeException` instead of proceeding with an unsecured parser. This is a necessary safety mechanism to ensure the XXE vulnerability cannot be bypassed on platforms where the security features are not recognized.

**Parser behavior on DTD/entity references:** After hardening, any XML containing DOCTYPE declarations, external entity references, or XInclude statements will have those features disabled. The parser will either:
- Reject the document if DOCTYPE is present and disallowed
- Expand external entity references to empty strings (document parses but entities vanish)
- Skip XInclude processing

The current code does not validate the parsed structure for empty or missing elements, so silently expanding entities to empty strings is acceptable here. If strict validation becomes necessary (rejecting documents with external entities entirely), a custom EntityResolver can be installed to throw an exception on entity resolution attempts.

**No changes to method signature, parameters, or return value.** The fix modifies parser configuration only and preserves the existing exception handling for `ParserConfigurationException` and `SAXException`.
