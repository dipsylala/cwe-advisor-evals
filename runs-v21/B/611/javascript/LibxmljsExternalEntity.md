## Verdict

Real XXE vulnerability in libxmljs. The parser processes external entity references by default, allowing attackers to read arbitrary files, perform SSRF attacks, or cause denial of service by supplying crafted XML with entity declarations. The vulnerability is compounded by libxmljs being unmaintained with unfixed CVEs (CVE-2024-34391, CVE-2024-34394 with no patched release).

## Source

File: `LibxmljsExternalEntity.js`, line 10-13

```javascript
const rawOrderXml = req.body;  // untrusted XML from HTTP POST
const doc = libxmljs.parseXml(rawOrderXml);  // XXE sink - processes external entities
```

An attacker can supply XML with external entity declarations:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<order>
  <id>&xxe;</id>
</order>
```

The parser resolves `&xxe;` and exposes file contents in the response.

## Fix

Replace `libxmljs` with `fast-xml-parser` configured with XXE protections enabled.

### File: LibxmljsExternalEntity.js

```javascript
const express = require('express');
const { XMLParser } = require('fast-xml-parser');

const app = express();

// Accept raw XML bodies posted by trading partners for order import.
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // Use fast-xml-parser with XXE protections
  const parser = new XMLParser({
    processEntities: false,  // Disable entity processing to prevent XXE
    parseTagValue: false     // Keep all values as strings
  });
  const doc = parser.parse(rawOrderXml);

  // fast-xml-parser returns a plain object; access nested properties directly
  const orderId = doc.order?.id;
  if (!orderId) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId: orderId });
});

module.exports = app;
```

## Explanation

The fix replaces the vulnerable `libxmljs` library (which binds unmaintained libxml2 with unfixed XXE CVEs) with `fast-xml-parser`, an actively maintained parser configured with XXE protections.

**Key changes:**
1. **Library replacement**: `libxmljs` → `fast-xml-parser` with `XMLParser` class
2. **XXE protection**: `processEntities: false` disables external entity processing at the parser level, preventing entity resolution
3. **Type preservation**: `parseTagValue: false` keeps all values as strings (matching the original `.text()` behavior)
4. **API migration**: DOM-style XPath (`doc.get('//order/id')`) replaced with direct object property access (`doc.order?.id`)

The `processEntities: false` configuration is the core XXE defence—it prevents the parser from resolving any external entity declarations in DOCTYPE sections or inline, eliminating the attack surface entirely.

## Behaviour changes

1. **XML parsing API**: Switches from DOM-like interface with XPath queries to plain JavaScript object access. This requires changing `doc.get('//order/id')` to `doc.order?.id`. The result is functionally equivalent for well-formed XML with standard structure, but deeply nested or XPath-complex queries would need restructuring.

2. **Return type**: `orderId` is now a string directly (no `.text()` method call needed). With `parseTagValue: false`, numeric-looking values remain strings rather than being converted to numbers.

3. **Dependency**: Removes `libxmljs` dependency and adds `fast-xml-parser`. This is a breaking change at the package level but necessary to eliminate the unfixed XXE vulnerability.

4. **Error handling**: Malformed XML in `parse()` throws an error (same as `parseXml()` would); no change to error semantics.

The fix fully closes CWE-611 by disabling the entity processing that enables XXE attacks, while preserving the application's core functionality of parsing order XML and extracting the order ID.
