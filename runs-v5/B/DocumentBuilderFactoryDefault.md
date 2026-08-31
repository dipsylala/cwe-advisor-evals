## Verdict

exploitable

- **cwe_id**: CWE-611
- **location**: `DocumentBuilderFactoryDefault.java`, line 24 (sink); factory constructed at line 21
- **confidence**: high

## Source

`request.getParameter("orderXml")` (line 18) - attacker-controlled request parameter, assigned directly to `orderXml` with no validation or transformation before it reaches the parser.

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
import javax.xml.XMLConstants;
// ... existing imports

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

## Explanation

`DocumentBuilderFactory.newInstance()` returns a factory whose default JAXP configuration resolves DOCTYPE declarations and external entities, so `orderXml` (taken unmodified from the HTTP request parameter) reaches `builder.parse()` with no restriction on external entity resolution - a crafted `<!DOCTYPE>` with an external or parameter entity can read local files, trigger SSRF, or exhaust resources. The fix configures the factory, before `newDocumentBuilder()` is called, to reject DOCTYPE declarations outright (`disallow-doctype-decl`, the strongest and primary control per the loaded guidance) and additionally disables external general/parameter entities, external DTD loading, XInclude, and entity-reference expansion, plus locks down `accessExternalDTD`/`accessExternalSchema` as defense-in-depth. `FEATURE_SECURE_PROCESSING` is set as well but is documented as an implementation-limits (DoS) control, not the mechanism that closes this finding. Every hardening call is a `setFeature`/`setAttribute` on `DocumentBuilderFactory`, which can throw `ParserConfigurationException` if a feature URI is unrecognized; that exception type is already caught by the existing `catch (ParserConfigurationException | SAXException e)` block, so no new exception handling is required.

## Behaviour changes

- A request body containing `<!DOCTYPE ...>` now fails to parse (`SAXException`, since `disallow-doctype-decl` is set) instead of being parsed and potentially having its entities resolved. This is caught by the existing `catch (... | SAXException e)` block and returns HTTP 400, same as any other malformed-XML input today - callers submitting a legitimate order document without a DOCTYPE see no change in behavior or response.
- No other arguments, return values, or output were altered: `builder.parse()` is called with the same `InputSource`/`StringReader` construction, and the downstream use of `doc` (`getElementsByTagName("customerId")`) is unchanged.
