## Verdict

Exploitable. The code parses untrusted XML input from HTTP request bodies using `libxmljs.parseXml()` without any XXE protection. An attacker can submit XML containing external entity references to read local files, perform SSRF attacks, or cause denial of service through entity expansion.

## Source

User-supplied XML in the HTTP POST request body (`req.body`), accepted via `express.text({ type: 'application/xml' })` and passed directly to the parser without validation or sanitization.

## Fix

**Dependency Change:**

Replace `libxmljs` with `xml2js`. The libxmljs library carries CVE-2024-34391 with no patched release, and CVE-2024-34394 in the unmaintained libxmljs2 fork. xml2js is built on sax-js, which never implemented DTD fetching, making it secure by default for XXE.

Update `package.json`:
```
- "libxmljs": "...",
+ "xml2js": "^0.6.2"
```

**Code Change:**

**Vulnerable code:**
```javascript
const libxmljs = require('libxmljs');

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
  const doc = libxmljs.parseXml(rawOrderXml);

  const orderId = doc.get('//order/id');
  if (!orderId) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId: orderId.text() });
});
```

**Fixed code:**
```javascript
const xml2js = require('xml2js');

const xmlParser = new xml2js.Parser({
  explicitArray: false,
  mergeAttrs: true
});

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // xml2js.parseStringPromise parses XML without DTD or external entity support
  xmlParser.parseString(rawOrderXml, (err, result) => {
    if (err) {
      return res.status(400).send('invalid XML');
    }

    const orderId = result?.order?.id;
    if (!orderId) {
      return res.status(400).send('missing order id');
    }

    res.json({ orderId: orderId });
  });
});
```

## Explanation

The vulnerability is eliminated by replacing libxmljs (which binds to libxml2 and can resolve external entities) with xml2js (which uses sax-js, a parser that never implemented DTD processing). xml2js is secure by default because the underlying sax-js parser does not support DOCTYPE declarations or external entity fetching at all. The parser configuration options in xml2js do not control XXE behavior because XXE attacks are structurally impossible in sax-js. External entity references in incoming XML are treated as literal text and ignored. This closes the path for XXE injection attacks (file disclosure, SSRF, entity expansion DoS) while preserving the application's ability to parse and extract order IDs from well-formed XML.

## Behaviour changes

The callback-based API differs from libxmljs's synchronous interface. Error handling now requires a callback check (the `err` parameter) rather than relying on exception throwing. The return value from `parseString()` is undefined; the parsed result is passed as the callback's second parameter. XPath queries (`.get('//order/id')`) are replaced with property navigation on the parsed object structure (`result?.order?.id`). xml2js converts XML elements to nested JavaScript objects, so XPath expressions are not supported; this changes how the code navigates the parsed structure, but the extraction of the order ID works the same way semantically. The parser options `explicitArray: false` and `mergeAttrs: true` are set to provide familiar object-like access patterns similar to XPath-based navigation; these are architectural choices that do not affect security.
