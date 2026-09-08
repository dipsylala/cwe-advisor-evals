## Verdict

Confirmed. `DocumentBuilderFactory.newInstance()` produces a `DocumentBuilder` with external entity and external DTD processing enabled by default. The code parses `orderXml`, which comes directly from an HTTP request parameter (`request.getParameter("orderXml")`), with no hardening applied to the factory. An attacker can submit a request body containing a `DOCTYPE` declaration with an external or parameter entity to read local files, perform SSRF, or exhaust resources via entity expansion.

## Source

`request.getParameter("orderXml")` in `handleOrderUpload` (line 18) - attacker-controlled HTTP request parameter, passed unmodified into `builder.parse(new InputSource(new StringReader(orderXml)))` at line 24.

## Fix

### File: DocumentBuilderFactoryDefault.java

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
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
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

The primary defense is `disallow-doctype-decl`, which rejects any document containing a `DOCTYPE` declaration outright - since this application's order payload has no legitimate need for a DTD, this is the strictest and most effective setting: it blocks external entities, parameter entities, and billion-laughs-style internal entity expansion in one step, because none of them can be declared without a `DOCTYPE`. The `external-general-entities` and `external-parameter-entities` feature flags are set to `false` as defense-in-depth in case a future change relaxes `disallow-doctype-decl` for a legitimate reason. `setXIncludeAware(false)` (the JAXP default, set explicitly here) and `setExpandEntityReferences(false)` close the related XInclude and internal-entity-expansion vectors. These calls must be made on the factory before `newDocumentBuilder()` is called, since the builder is configured at creation time. The catch block already handles `SAXException`, which is what `disallow-doctype-decl` causes the parser to throw when a `DOCTYPE` is present, so malicious input now fails safely with an HTTP 400 instead of being parsed.
