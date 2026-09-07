## Verdict
CONFIRMED

## Source
Line 24 in DocumentBuilderFactoryDefault.java - the DocumentBuilderFactory is created with default settings without XXE protections, allowing an attacker to inject malicious XML entities through the `orderXml` parameter to read files, cause denial of service, or perform other attacks.

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
import javax.xml.XMLConstants;

public class DocumentBuilderFactoryDefault {

    public void handleOrderUpload(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String orderXml = request.getParameter("orderXml");

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
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
The fix disables XXE processing by configuring the DocumentBuilderFactory with several protections before parsing user-supplied XML:

1. **Disallow DOCTYPE declarations** (`disallow-doctype-decl`): Prevents the parser from processing DOCTYPE declarations that could define entities.
2. **Disable external general entities** (`external-general-entities`): Blocks general entity expansion from external sources.
3. **Disable external parameter entities** (`external-parameter-entities`): Blocks parameter entity expansion from external sources.
4. **Disable external DTD loading** (`nonvalidating/load-external-dtd`): Prevents loading of external DTD files.
5. **Restrict DTD and Schema access** (`ACCESS_EXTERNAL_DTD`, `ACCESS_EXTERNAL_SCHEMA`): Sets empty string to deny all external access.
6. **Disable XInclude** (`setXIncludeAware`): Prevents XML inclusion attacks.
7. **Disable entity reference expansion** (`setExpandEntityReferences`): Disables automatic entity replacement.

These settings allow normal XML parsing while preventing XXE attacks, ensuring that the application safely processes untrusted XML input.
