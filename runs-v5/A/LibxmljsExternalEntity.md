## Verdict

Confirmed. `/orders/import` parses attacker-supplied XML from the request body with `libxmljs.parseXml()` and no explicit parser options, then reads values out of the resulting document and reflects one of them (`orderId`) back in the response. Without an explicit, hardened parser configuration, a submitted document that declares a `DOCTYPE` with an external or parameter entity can be resolved during parsing, letting a trading partner read local files, reach internal/network-only endpoints (SSRF), or exhaust memory/CPU via nested entity expansion.

## Source

`req.body` in the `POST /orders/import` handler (`LibxmljsExternalEntity.js`, line 10) — raw XML bytes taken directly from the HTTP request body via `express.text({ type: 'application/xml' })`, fully attacker-controlled with no schema or entity restrictions applied before use.

## Fix

```javascript
const express = require('express');
const libxmljs = require('libxmljs');

const app = express();

app.use(express.text({ type: 'application/xml' }));

const HAS_DOCTYPE = /<!DOCTYPE/i;

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // Order documents never need a DTD; reject any that declare one outright
  // rather than relying solely on parser flags to neutralize it.
  if (typeof rawOrderXml !== 'string' || HAS_DOCTYPE.test(rawOrderXml)) {
    return res.status(400).send('invalid order document');
  }

  // SAST FINDING (fixed): parse with entity/DTD/network resolution explicitly
  // disabled instead of relying on library defaults.
  const doc = libxmljs.parseXml(rawOrderXml, {
    noent: false,     // do not substitute entity references into the tree
    dtdload: false,   // do not fetch/load an external DTD subset
    dtdvalid: false,  // do not validate against a DTD
    nonet: true,       // forbid network access during parsing
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

The sink is the `libxmljs.parseXml(rawOrderXml)` call: it hands the full, unmodified request body to a native XML parser with no options object, so the effective parser configuration is whatever `libxmljs` and its underlying `libxml2` build ship as defaults, and that is not something a request handler for untrusted, cross-organization input should depend on implicitly. The fix does two independent things, either of which closes the immediate hole and together provide defense in depth:

1. **Reject any `DOCTYPE`.** A purchase-order document has no legitimate reason to declare a DTD or entities, so the simplest and most robust control is to refuse any input that contains a `<!DOCTYPE` marker before it ever reaches the parser. This removes the entire attack surface regardless of which parser flags are set or how a future library upgrade changes its defaults.
2. **Pass an explicit, restrictive options object to `parseXml`.** `noent: false` keeps entity references unexpanded rather than substituted into the parsed tree, `dtdload: false` and `dtdvalid: false` stop the parser from fetching or validating against an external DTD subset, and `nonet: true` blocks any network fetch the parser might otherwise attempt while resolving a reference. Making these choices explicit means the security posture of this endpoint no longer depends on the ambient default of whichever `libxmljs`/`libxml2` version is installed.

Because the first control alone eliminates the entity-declaration vector, the fix is safe to apply even without deeper certainty about the exact default flags of the installed `libxmljs` build, and the explicit parser options remove that uncertainty going forward. After applying the fix, verify with a request whose body is `<?xml version="1.0"?><!DOCTYPE order [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><order><id>&xxe;</id></order>` and confirm the endpoint returns `400` rather than echoing file contents or attempting an outbound connection; also confirm a normal `<order><id>123</id></order>` payload still parses and returns `{"orderId":"123"}`.
