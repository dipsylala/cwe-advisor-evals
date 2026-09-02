## Verdict

Exploitable. `DocumentBuilderFactory.newInstance()` returns a factory with DTD processing and external entity resolution enabled by default, and no hardening feature is set anywhere on the `factory` or `builder` objects before `builder.parse()` is called. An attacker-supplied `orderXml` body containing a `<!DOCTYPE>` with an external or parameter entity will be resolved by the parser, enabling file disclosure, SSRF, or denial of service. The finding at line 24 is confirmed.

## Source

`request.getParameter("orderXml")` (line 18) - the raw HTTP request parameter `orderXml`, fully attacker-controlled, flows unmodified into `new StringReader(orderXml)` -> `new InputSource(...)` -> `builder.parse(...)` at line 24 with no validation or sanitization in between.

## Fix

Vulnerable code:

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
// SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

Fixed code:

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

(Requires adding `import javax.xml.XMLConstants;` alongside the existing imports.)

## Explanation

The fix configures `DocumentBuilderFactory` to reject DTDs outright via `disallow-doctype-decl`, which is the setting that actually stops entity-based attacks (`FEATURE_SECURE_PROCESSING` alone only bounds implementation limits like entity expansion counts, it does not block resolution). The external-general-entities, external-parameter-entities, and load-external-dtd features are disabled as defense-in-depth in case a future change relaxes the DOCTYPE ban, XInclude processing is turned off since it is a separate external-reference vector, and `accessExternalDTD`/`accessExternalSchema` are set to the empty string to close JAXP's own external-access properties. All settings are applied to the factory before `newDocumentBuilder()` is called, so they take effect for the parser instance used at the line-24 sink. Each `setFeature` call can throw `ParserConfigurationException`, which the existing `catch (ParserConfigurationException | SAXException e)` block already handles, so no exception-handling changes are required.

## Behaviour changes

- Any `orderXml` payload containing a `<!DOCTYPE` declaration - including one with no external or parameter entity, i.e. a benign or well-formed internal DTD - will now cause `builder.parse()` to throw `SAXException`, which the existing catch block turns into an HTTP 400 response instead of a parsed document. This is the intended effect of rejecting DOCTYPE outright (the strongest option per the loaded guidance) and is a legitimate behavior change for any caller that was relying on DOCTYPE-bearing input succeeding.
- No other behavior changes: the return value of `parse()`, the success-path handling of `customerId`, and the response-writing logic are unchanged. No arguments to `parse()` itself were altered, and no discarded output is now surfaced.

Assumption: no callers of `handleOrderUpload` are expected to submit XML containing a legitimate DOCTYPE declaration, since none is referenced in the order-processing logic (only `customerId` is read); this was resolved without asking per autonomous mode.
