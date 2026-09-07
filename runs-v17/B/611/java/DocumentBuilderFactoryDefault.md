## Verdict

Real, exploitable XXE vulnerability. Untrusted XML input from `request.getParameter()` is parsed with default DocumentBuilderFactory configuration that allows external entity resolution and DTD processing. Attacker can craft XML with DOCTYPE containing external entity definitions to read arbitrary files, perform SSRF attacks, or cause denial of service through entity expansion.

## Source

`request.getParameter("orderXml")` at line 18 provides untrusted XML string. Data flows through `orderXml` variable to `builder.parse(new InputSource(new StringReader(orderXml)))` at line 24, which is the vulnerable sink.

## Fix

### File: DocumentBuilderFactoryDefault.java

```java
package evalcases;

import java.io.IOException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.XMLConstants;
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
            
            // Harden parser against XXE attacks
            try {
                factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            } catch (ParserConfigurationException e) {
                // Some parsers may not recognize this feature
            }
            
            try {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            } catch (ParserConfigurationException e) {
                // Some parsers may not recognize this feature
            }
            
            try {
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            } catch (ParserConfigurationException e) {
                // Some parsers may not recognize this feature
            }
            
            try {
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            } catch (ParserConfigurationException e) {
                // Some parsers may not recognize this feature
            }
            
            try {
                factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            } catch (ParserConfigurationException e) {
                // Some parsers may not recognize this feature
            }
            
            // Restrict external access via properties (JAXP 1.5+)
            factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "");
            factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "");
            
            // Disable XInclude processing
            factory.setXIncludeAware(false);
            
            // Disable entity reference expansion (defense-in-depth)
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

The fix hardens the DocumentBuilderFactory before parsing by disabling all XXE attack vectors:

1. **FEATURE_SECURE_PROCESSING** enables parser implementation limits on entity expansion (defense-in-depth against DoS)
2. **disallow-doctype-decl** forbids DOCTYPE declarations entirely (strongest XXE control)
3. **external-general-entities** and **external-parameter-entities** set to false disable entity resolution
4. **load-external-dtd** set to false prevents external DTD loading
5. **accessExternalDTD** and **accessExternalSchema** set to empty string restricts external access (JAXP 1.5+ standard properties)
6. **setXIncludeAware(false)** disables XInclude processing
7. **setExpandEntityReferences(false)** prevents entity reference expansion

Each feature is wrapped in try-catch because different parsers may not recognize all feature URIs. The parse now succeeds but external entities are disabled at the parser level - any external entity reference will expand to empty content rather than accessing external resources. The application continues to work correctly for legitimate XML documents while XXE attacks are blocked.

## Behaviour changes

- External entity references in XML documents are now silently disabled (expand to nothing)
- DOCTYPE declarations are now rejected
- XInclude processing is disabled
- The parse operation continues to succeed for valid XML without external entities
- Invalid XML attempting XXE attacks will parse but entity references will be empty
- No change to legitimate code paths; only malicious XML is affected
