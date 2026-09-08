## Verdict

Vulnerable. The code parses untrusted XML from a user-controlled request body without disabling external entity processing, allowing an attacker to read local files, perform SSRF, trigger DoS, or exfiltrate data.

## Source

**File:** LibxmljsExternalEntity.js  
**Line:** 13

```javascript
const doc = libxmljs.parseXml(rawOrderXml);
```

The `parseXml()` call accepts untrusted XML (`rawOrderXml` from `req.body`) without specifying options to disable external entity expansion. By default, libxmljs allows DTD loading and entity substitution, enabling XXE attacks.

## Fix

### File: LibxmljsExternalEntity.js

```javascript
const express = require('express');
const libxmljs = require('libxmljs');

const app = express();

// Accept raw XML bodies posted by trading partners for order import.
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // Disable external entity processing to prevent XXE
  const doc = libxmljs.parseXml(rawOrderXml, {
    dtdload: false,
    dtdvalid: false,
    noent: false
  });

  const orderId = doc.get('//order/id');
  if (!orderId) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId: orderId.text() });
});

module.exports = app;
```

## Explanation

The fix passes a second options parameter to `libxmljs.parseXml()` with three settings that collectively disable XXE attack vectors:

1. **`dtdload: false`** — Prevents loading of external DTDs from network or filesystem sources, blocking the primary XXE vector.

2. **`dtdvalid: false`** — Disables DTD validation, eliminating parameter entity expansion during validation.

3. **`noent: false`** — Disables entity substitution, preventing the parser from expanding both internal and external entity references. This closes the secondary XXE path used when entities are invoked mid-parse.

Together, these options ensure the XML parser accepts the structure and content of the XML but rejects any directives that reference external resources or expand entities, while maintaining the ability to extract order data via standard XPath queries like `//order/id`.
