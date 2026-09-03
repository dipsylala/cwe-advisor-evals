## Verdict

Exploitable XXE vulnerability confirmed. The application parses untrusted XML from trading partners using `libxmljs.parseXml()` without disabling external entity resolution. The parser can fetch external entities, allowing attackers to read local files, perform SSRF attacks, or cause denial of service through entity expansion.

Additionally, `libxmljs` carries unfixed CVE-2024-34391; the library is unmaintained and no patched release exists.

## Source

- **Input source:** `req.body` (HTTP POST request body, application/xml)
- **Attacker control:** Full - trading partners submit XML directly
- **Entry point:** Line 10: `const rawOrderXml = req.body;`
- **Vulnerable sink:** Line 13: `const doc = libxmljs.parseXml(rawOrderXml);`

Data flows directly from untrusted input to the parser with no intermediate validation or filtering.

## Fix

Replace `libxmljs` with `xml2js`, which is built on `sax-js`—a parser that never implemented DTD fetching and therefore cannot process external entities.

**Dependency change:**
```
"libxmljs": "..." → "xml2js": "^0.5.0"
```

**Code fix:**

```javascript
const express = require('express');
const xml2js = require('xml2js');

const app = express();

// Accept raw XML bodies posted by trading partners for order import.
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // Parse XML with xml2js (sax-based parser, no DTD/external entity support)
  const parser = new xml2js.Parser();
  parser.parseString(rawOrderXml, (err, doc) => {
    if (err) {
      return res.status(400).send('invalid xml');
    }

    const orderId = doc?.order?.[0]?.id?.[0];
    if (!orderId) {
      return res.status(400).send('missing order id');
    }

    res.json({ orderId: orderId });
  });
});

module.exports = app;
```

## Explanation

`libxmljs` binds libxml2, which resolves external entities by default and can be exploited for XXE attacks (file disclosure, SSRF, DoS). Additionally, libxmljs carries CVE-2024-34391 with no patched release and is unmaintained.

`xml2js` is built on `sax-js`, a SAX parser that never implemented DTD fetching. External entity references are not expanded—the parser simply rejects or ignores DOCTYPE declarations. This eliminates XXE as an attack vector at the parser level.

The fix replaces the library and adjusts the parsing API (xml2js uses a callback-based asynchronous interface and returns a JavaScript object structure rather than a libxmljs Document). The XPath-like query (`doc.get()`) is replaced with safe nested property access.

## Behaviour changes

- **Parser API:** Switched from synchronous libxmljs Document API to asynchronous xml2js callback pattern
- **Data structure:** Result is a plain JavaScript object, not a libxmljs Document instance
- **Element access:** Changed from `doc.get('//order/id').text()` to `doc?.order?.[0]?.id?.[0]` (xml2js represents repeated elements as arrays)
- **Error handling:** Added explicit error callback for parsing failures
- **Security posture:** External entity processing is structurally impossible—no configuration, no CVEs, no unmaintained library
- **XXE vector:** Closed; DOCTYPE declarations are rejected by the underlying SAX parser
