## Verdict

Exploitable. The code parses untrusted XML input using `libxmljs.parseXml()` without disabling external entity resolution. An attacker can submit XML with DOCTYPE containing external entity definitions to read local files, perform SSRF attacks, or cause denial of service.

## Source

Untrusted XML input from HTTP POST body (`req.body`, line 10) flows directly to the XML parser.

## Fix

**Root Cause:**
libxmljs binds libxml2 and carries unfixed CVEs (CVE-2024-34391 with no patched release; libxmljs2 fork also broken with CVE-2024-34394 and repository gone). The library cannot be safely configured—it must be replaced.

**Vulnerable Code:**
```javascript
const express = require('express');
const libxmljs = require('libxmljs');

const app = express();
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here.
  const doc = libxmljs.parseXml(rawOrderXml);

  const orderId = doc.get('//order/id');
  if (!orderId) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId: orderId.text() });
});

module.exports = app;
```

**Fixed Code:**
Replace libxmljs with `fast-xml-parser` and disable entity processing:

```javascript
const express = require('express');
const FastXmlParser = require('fast-xml-parser');

const app = express();
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // Parse XML with external entity processing disabled
  const parser = new FastXmlParser.XMLParser({ processEntities: false });
  const doc = parser.parse(rawOrderXml);

  const orderId = doc?.order?.id;
  if (!orderId) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId });
});

module.exports = app;
```

**Dependency Change:**
- Remove: `libxmljs` from package.json
- Add: `fast-xml-parser` (no specific version in guidance; verify against current stable release and SCA tooling before deploying)

## Explanation

libxmljs is fundamentally unsuitable for untrusted XML input because it binds libxml2 and carries unfixed CVEs that allow external entity resolution. The fix replaces it with `fast-xml-parser`, which provides synchronous parsing and respects the `processEntities: false` option to disable entity expansion entirely. This prevents both XXE file disclosure and denial-of-service attacks.

The code adapts to fast-xml-parser's object-based output model (replacing libxmljs's xpath `.get()` and `.text()` methods with direct object property access). The security property—rejecting malicious entity definitions—is achieved by disabling entity processing at parse time, not by validation.

## Behaviour changes

**API change:** fast-xml-parser returns plain JavaScript objects; libxmljs returns Node objects with xpath methods. Property access changes from `doc.get('//order/id').text()` to `doc?.order?.id`.

**Error handling:** fast-xml-parser does not throw on invalid XML by default; it returns an object or empty result. The null-check on `orderId` covers both missing element and parse failure cases.

**Synchronous execution:** Both libraries parse synchronously at line 13; no async restructuring needed.

**Response format:** The orderId is now a string directly, not a Node object. The `.json()` serialization is compatible with both (libxmljs Node.text() returns a string).
