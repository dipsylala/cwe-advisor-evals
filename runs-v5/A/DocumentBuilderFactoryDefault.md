## Verdict

Confirmed. `DocumentBuilderFactory.newInstance()` produces a factory with external entity and DTD processing enabled by default, and the `DocumentBuilder` built from it parses attacker-controlled XML, making this a classic XXE vulnerability.

## Source

`request.getParameter("orderXml")` (line 18) - the raw `orderXml` HTTP request parameter is attacker-controlled and flows unmodified into the parser.

## Fix

```java
package evalcases;

import java.io.IOException;
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

            // Disallow DOCTYPE declarations entirely - the strongest defense against
            // both classic XXE and XML entity-expansion (billion laughs) attacks.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            // Defense in depth in case DOCTYPEs are ever re-enabled for a legitimate
            // reason: keep external general/parameter entities and external DTD
            // fetches off, and turn off XInclude processing.
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

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

`DocumentBuilderFactory.newInstance()` returns a factory that, by default, resolves DOCTYPE declarations and both external general and parameter entities. An attacker who controls `orderXml` can submit a document with a `<!DOCTYPE>` block defining an external entity (e.g. pointing at a `file://` URI or an internal/SSRF-reachable URL), and have its resolved content substituted into the document the application then reads back out via `getElementsByTagName(...).getTextContent()` - disclosing local files or enabling SSRF/DoS (entity expansion, external DTD fetches).

The fix sets `disallow-doctype-decl` to `true`, which is the standard OWASP-recommended hardening for `DocumentBuilderFactory`: it rejects any document containing a DOCTYPE outright, which is sufficient for this use case since legitimate order XML has no reason to declare one. The additional `setFeature`/`setXIncludeAware`/`setExpandEntityReferences` calls are defense-in-depth for the case where a DOCTYPE-permitting code path is introduced later - they ensure external entities, external DTD loading, and XInclude are all still disabled even if the primary guard is relaxed. Because `disallow-doctype-decl` causes any XML containing a DOCTYPE to raise a `SAXParseException`, the existing `catch (ParserConfigurationException | SAXException e)` block already handles the rejection path by returning HTTP 400, so no additional error handling is required.
