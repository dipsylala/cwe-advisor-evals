## Verdict

Confirmed. `DocumentBuilderFactory.newInstance()` is used with its default configuration, which leaves DOCTYPE processing, external general entities, external parameter entities, and external DTD loading all enabled. `builder.parse()` is called directly on `orderXml`, which comes from `request.getParameter("orderXml")` (attacker-controlled, unbounded). An attacker can submit a document such as:

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<order><customerId>&xxe;</customerId></order>
```

and have its contents reflected back in the HTTP response via `customerId`, or trigger SSRF/blind exfiltration through a `SYSTEM` URL pointing at an internal or external host. This is a classic XXE sink (CWE-611).

## Source

`String orderXml = request.getParameter("orderXml");` (line 18) — untrusted HTTP request parameter, flows unmodified into `builder.parse(new InputSource(new StringReader(orderXml)))` at line 24.

## Fix

Harden the `DocumentBuilderFactory` before creating the builder, disabling DTDs and external entity resolution entirely (the order upload has no legitimate need for either):

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

            // Reject any document containing a DOCTYPE declaration. This alone
            // blocks classic XXE and billion-laughs style entity expansion.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

            // Defense in depth in case DOCTYPE processing cannot be fully disabled
            // by the underlying parser implementation.
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

`disallow-doctype-decl` is the primary defense: it makes the parser throw a `SAXException` the moment it encounters any `<!DOCTYPE ...>` declaration, so no entity — internal or external — can ever be defined in the first place, and it also stops entity-expansion (billion laughs) denial-of-service. Since this feature is set to `true`, the two `external-*-entities` and `load-external-dtd` features are technically redundant for a compliant parser, but they are cheap, no-op-safe, and protect against XML parser implementations or future refactors that relax the DOCTYPE rejection while still allowing entities to resolve. `setXIncludeAware(false)` (the JDK default, stated explicitly here) blocks a separate XInclude-based file-read vector that DOCTYPE rejection does not cover. `setExpandEntityReferences(false)` ensures any entity reference nodes that do slip through are left unexpanded in the DOM rather than resolved.

The existing `catch (ParserConfigurationException | SAXException e)` block already handles the case where a malicious upload now throws (DOCTYPE present), returning HTTP 400 exactly as it does for any other malformed XML — no additional error-handling changes are required. Legitimate order XML, which has no reason to declare a DOCTYPE or entity, is unaffected by any of these settings.
