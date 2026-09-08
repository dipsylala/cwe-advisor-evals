## Verdict

CONFIRMED - CWE-611 XXE vulnerability. The code uses `DocumentBuilderFactory` with default configuration to parse untrusted XML from user input (`orderXml` parameter), allowing XML External Entity injection attacks.

## Source

The vulnerable code at line 24 parses untrusted user input without disabling external entity processing:

```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(orderXml)));
```

The factory's default configuration leaves DTD processing and external entity resolution enabled, permitting attackers to inject malicious entity definitions to read files, perform SSRF, or cause denial of service.

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
            
            // Disable XXE and DTD processing to prevent XXE attacks
            disableXXEAttacks(factory);
            
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(orderXml)));

            String customerId = doc.getElementsByTagName("customerId").item(0).getTextContent();
            response.getWriter().write("Order received for customer: " + customerId);
        } catch (ParserConfigurationException | SAXException e) {
            response.setStatus(400);
        }
    }
    
    private void disableXXEAttacks(DocumentBuilderFactory factory) {
        // Disallow DOCTYPE declarations
        try {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            // Feature not supported, continue
        }
        
        // Enable secure processing
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        } catch (ParserConfigurationException e) {
            // Feature not supported, continue
        }
        
        // Disable external general entities
        try {
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        } catch (ParserConfigurationException e) {
            // Feature not supported, continue
        }
        
        // Disable external parameter entities
        try {
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        } catch (ParserConfigurationException e) {
            // Feature not supported, continue
        }
        
        // Disable external DTD loading
        try {
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        } catch (ParserConfigurationException e) {
            // Feature not supported, continue
        }
        
        // Disable XInclude and entity reference expansion
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        
        // Restrict external DTD access
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (IllegalArgumentException e) {
            // Attribute not supported, continue
        }
        
        // Restrict external schema access
        try {
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (IllegalArgumentException e) {
            // Attribute not supported, continue
        }
    }
}
```

## Explanation

The fix hardens the `DocumentBuilderFactory` with a comprehensive set of XXE protections applied before parsing occurs:

1. **Disallow DOCTYPE declarations** - The strongest primary control; blocks DTD processing entirely.

2. **Enable secure processing** - Sets implementation limits on entity expansion to defend against billion laughs DoS.

3. **Disable external entities** - Blocks both general and parameter entity resolution.

4. **Disable external DTD loading** - Prevents the parser from fetching external DTDs.

5. **Disable XInclude and entity reference expansion** - Removes additional XML processing features that could be abused.

6. **Restrict external access** - Sets `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` to empty strings, blocking file system and network access from the parser.

Each feature configuration is wrapped in try-catch because some parsers may not recognize all features, and a configuration that throws defeats the purpose. The helper method keeps the main logic clean and the hardening reusable if similar parsing occurs elsewhere.

The defenses work in defense-in-depth: disallow-doctype-decl stops most attacks, but external entity features provide redundant protection. If an element is missing due to hardening (entity expands to nothing), the application still processes normally with an empty value rather than rejecting the document entirely.
