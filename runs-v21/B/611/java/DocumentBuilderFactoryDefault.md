## Verdict

CONFIRMED: CWE-611 (Improper Restriction of XML External Entity Reference)

The vulnerable code parses untrusted XML from an HTTP request parameter using a DocumentBuilderFactory with default settings, which allow DTD processing and external entity resolution. An attacker can supply malicious XML with external entity declarations to read files, perform SSRF attacks, or cause denial of service.

## Source

HTTP request parameter `orderXml` at line 18 is read and passed directly to the XML parser at line 24 without XXE hardening.

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
            
            // Disable DTDs and external entity processing to prevent XXE attacks
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            
            // Disable DOCTYPE declarations
            try {
                factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            } catch (ParserConfigurationException e) {
                // Feature not recognized by this parser implementation
            }
            
            // Disable external general entities
            try {
                factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            } catch (ParserConfigurationException e) {
                // Feature not recognized by this parser implementation
            }
            
            // Disable external parameter entities
            try {
                factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            } catch (ParserConfigurationException e) {
                // Feature not recognized by this parser implementation
            }
            
            // Disable external DTDs
            try {
                factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            } catch (ParserConfigurationException e) {
                // Feature not recognized by this parser implementation
            }
            
            // Restrict access to external entities and schemas
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            
            // Disable XInclude
            factory.setXIncludeAware(false);
            
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

The fix hardens the DocumentBuilderFactory before parsing begins by applying all XXE-prevention controls recommended in the Java guidance:

1. **FEATURE_SECURE_PROCESSING**: Enables implementation-level security constraints.
2. **disallow-doctype-decl**: The primary defense that disables DOCTYPE declarations entirely.
3. **external-general-entities**: Disables resolution of external general entity references.
4. **external-parameter-entities**: Disables resolution of external parameter entity references.
5. **load-external-dtd**: Prevents loading of external DTD files.
6. **ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA**: Restricts external access to the empty string (no access).
7. **XInclude**: Disabled to prevent XInclude attacks.

Each setFeature call is wrapped in a try-catch block because unrecognized feature URIs throw ParserConfigurationException in some parser implementations; this defensive wrapping ensures the fix works across different Java XML parser implementations while still applying protections that are available.

The factory configuration is applied before calling `newDocumentBuilder()`, ensuring all parser instances created from this factory inherit the hardened settings. The sink contract is preserved: the parse still returns a Document object as before, and the error handling remains unchanged.

## Behaviour changes

- External entity references in XML input are now blocked and will not resolve, causing them to expand to empty strings rather than accessing external resources.
- DOCTYPE declarations are now rejected during parsing.
- Parsing behavior is slightly more strict but remains compatible with well-formed XML that does not rely on external entities or DTDs.
- No functional change to legitimate use cases; invalid external entity references simply fail to resolve rather than being processed.
