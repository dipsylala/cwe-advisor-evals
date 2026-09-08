## Verdict

exploitable

- cwe_id: CWE-611
- location: `DocumentBuilderFactoryDefault.java`, line 24 (`builder.parse(...)`)
- confidence: high

## Source

`request.getParameter("orderXml")` at line 18 - an HTTP request parameter, fully attacker-controlled. It flows unmodified (no validation, encoding, or allowlist check anywhere in between) into `new StringReader(orderXml)` and then `new InputSource(...)` at line 24.

## Fix

### File: DocumentBuilderFactoryDefault.java

```java
package evalcases;

import java.io.IOException;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.StringReader;

public class DocumentBuilderFactoryDefault {

    public void handleOrderUpload(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String orderXml = request.getParameter("orderXml");

        try {
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

            String customerId = doc.getElementsByTagName("customerId").item(0).getTextContent();
            response.getWriter().write("Order received for customer: " + customerId);
        } catch (ParserConfigurationException | SAXException e) {
            response.setStatus(400);
        }
    }
}
```

## Explanation

`DocumentBuilderFactory.newInstance()` produces a parser with DTD and external-entity resolution enabled by default, so the attacker-controlled `orderXml` body reaches `builder.parse()` able to declare a `DOCTYPE` with an external or parameter entity - the classic XXE path to local file disclosure or SSRF. The fix configures the factory, before `newDocumentBuilder()` is called, with `disallow-doctype-decl` set `true`, which rejects any document containing a `DOCTYPE` declaration outright and is the setting that actually closes this weakness (per the language guidance, `FEATURE_SECURE_PROCESSING` alone only bounds implementation limits such as entity-expansion counts, it does not stop entity resolution). The external-general-entities, external-parameter-entities, and load-external-dtd features are disabled as defence-in-depth in case a future change relaxes the DOCTYPE rejection, `setXIncludeAware(false)` blocks the separate XInclude inclusion mechanism, and the `accessExternalDTD`/`accessExternalSchema` attributes are pinned to the empty string so the JAXP-level external-access properties can't be used to reach a DTD or schema over the network or filesystem even if a feature is later loosened. `setExpandEntityReferences(false)` is included as the guidance notes it is worth setting, though it is not itself the control that stops XXE. All settings are applied to the single `DocumentBuilderFactory` instance used by this method, before any parsing occurs.

## Behaviour changes

- Any `orderXml` value that contains a `<!DOCTYPE` declaration - benign or malicious - now fails to parse. `disallow-doctype-decl` throws a `SAXParseException` (a subclass of the already-caught `SAXException`), so the request now returns HTTP 400 instead of parsing the DOCTYPE. This is the intended effect of the fix (the guidance calls outright DOCTYPE rejection the strongest option) and only matters if some legitimate caller was relying on a DOCTYPE in the order XML, which is unlikely for a server-to-server order payload and was never a documented requirement here.
- No other behavior changes: return value, success-path output, and the existing `catch (ParserConfigurationException | SAXException)` / `response.setStatus(400)` error handling are unchanged. The added `setFeature`/`setAttribute` calls occur before `newDocumentBuilder()`, inside the same `try` block, so a `ParserConfigurationException` from an unrecognized feature URI is already caught by the existing catch clause - no new exception path was introduced.

## Verification

Compiled with `javac` (JDK 26) against stub `javax.servlet.http.HttpServletRequest`/`HttpServletResponse` interfaces (the real servlet API is a build dependency, not part of the JDK, and was not present on this machine so it was stubbed with only the two methods this file calls) in a scratch directory outside the repository - the fixed file compiled with no errors or warnings. Every added symbol (`XMLConstants.FEATURE_SECURE_PROCESSING`, `XMLConstants.ACCESS_EXTERNAL_DTD`, `XMLConstants.ACCESS_EXTERNAL_SCHEMA`, `DocumentBuilderFactory.setXIncludeAware`, `DocumentBuilderFactory.setExpandEntityReferences`, `DocumentBuilderFactory.setAttribute`, `DocumentBuilderFactory.setFeature`) is part of the standard `javax.xml.parsers`/`javax.xml.XMLConstants` JDK API named in the loaded language guidance, not a new third-party dependency.

## Assumptions

None - the CWE ID matched the finding description, the language was unambiguous from the file extension and imports, and the loaded guidance directly named every setting used.
