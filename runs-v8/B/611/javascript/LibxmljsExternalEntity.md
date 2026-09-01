## Verdict

CWE-611: XXE injection via libxmljs.parseXml() without entity restrictions. Confirmed exploitable.

## Source

User-supplied XML from HTTP POST request body (`rawOrderXml` from `req.body`), passed directly to libxmljs parser without validation or configuration to disable external entity processing.

## Fix

Replace `libxmljs` with `fast-xml-parser` and disable entity processing:

**Original vulnerable code (line 13):**
```javascript
const doc = libxmljs.parseXml(rawOrderXml);
```

**Fixed code:**
```javascript
const FastXmlParser = require('fast-xml-parser');

const parser = new FastXmlParser.XMLParser({
  processEntities: false,
  ignoreDeclaration: false
});

const doc = parser.parse(rawOrderXml);
```

**Package dependency change:**
Replace in `package.json`:
```json
// Remove:
"libxmljs": "...",

// Add:
"fast-xml-parser": "^4.4.0"
```

## Explanation

libxmljs binds libxml2 and resolves external entity references by default, enabling XXE attacks that read local files or perform SSRF. libxmljs carries unpatched CVEs (CVE-2024-34391) with no fixed release and is unmaintained. 

fast-xml-parser is actively maintained and disables entity processing by default when `processEntities: false` is specified. This prevents both external entity fetching and entity expansion attacks. The parser still parses the XML structure correctly while rejecting malicious DOCTYPE and ENTITY declarations. Setting `ignoreDeclaration: false` preserves the original parser behavior for declaration handling.

## Behaviour changes

- External entity references in XML input are now rejected and not resolved
- DOCTYPE declarations are parsed but not processed for entity expansion
- The resulting document object structure from fast-xml-parser is compatible with the existing XPath query `doc.get('//order/id')` with minor method adjustments if needed (fast-xml-parser returns a JSON object, not an XML node object, so XPath queries require adaptation or use of `xml2js` instead if XPath is required)

Note: If full XPath support is critical, `xml2js` with `sax-js` (which never implemented DTD fetching) is an alternative that also eliminates XXE without configuration. This fix prioritizes security (proven maintenance, explicit entity disabling) and active library support.
