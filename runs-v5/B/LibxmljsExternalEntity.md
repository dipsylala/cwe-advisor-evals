## Verdict

CWE-611 (Improper Restriction of XML External Entity Reference) - **exploitable**, confidence high.

## Source

`req.body` in the `POST /orders/import` handler: the raw HTTP request body, accepted as `application/xml` via `express.text({ type: 'application/xml' })` (line 7) and passed unmodified into `rawOrderXml` (line 10). It is fully attacker-controlled - a trading partner (or anyone able to reach the endpoint) supplies the entire XML document, including any `<!DOCTYPE>`/entity declarations, with no validation or filtering between the body parser and the parse call.

That value flows directly to the sink at line 13, `libxmljs.parseXml(rawOrderXml)`, with no options object - libxmljs binds libxml2 and, unlike most other Node XML parsers, can genuinely resolve external entities, so this is a live file-disclosure/SSRF sink, not just an entity-expansion DoS. The resulting document is queried (`doc.get('//order/id')`, line 15) and the matched value is echoed back to the caller in the JSON response (line 20), giving an attacker a read-back channel for anything an injected external entity resolves to.

## Fix

**Dependency note:** `libxmljs` has no parser-option fix here. It carries CVE-2024-34391 with no patched release, and its `libxmljs2` fork carries CVE-2024-34394, also unfixed, with the repository gone. The finding is the dependency itself, not a missing option, so the remediation is to replace the parser rather than harden its configuration. Replacement: `fast-xml-parser`, which does not fetch external entities/DTDs at all; pair it with `processEntities: false` to also disable in-document entity substitution. The knowledge base gives no minimum version for `fast-xml-parser` - confirm the resolved version against SCA/dependency-check tooling before merging.

Vulnerable code (`LibxmljsExternalEntity.js`, lines 9-21):

```javascript
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

Fixed code:

```javascript
const express = require('express');
const { XMLParser } = require('fast-xml-parser');

const app = express();

// Accept raw XML bodies posted by trading partners for order import.
app.use(express.text({ type: 'application/xml' }));

// libxmljs (and its libxmljs2 fork) carry unpatched XXE CVEs with no fixed release, so it is
// replaced rather than reconfigured. fast-xml-parser does not fetch external entities/DTDs;
// processEntities: false additionally disables in-document entity substitution.
// parseTagValue: false keeps element text as strings, matching libxmljs's .text() behaviour.
const xmlParser = new XMLParser({ processEntities: false, parseTagValue: false });

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  const doc = xmlParser.parse(rawOrderXml);

  const orderId = doc?.order?.id;
  if (orderId === undefined) {
    return res.status(400).send('missing order id');
  }

  res.json({ orderId });
});

module.exports = app;
```

## Explanation

The weakness is closed by removing `libxmljs` from the parse path rather than trying to configure it safely, because both it and its maintained-fork alternative have XXE CVEs with no fix available - any option-level mitigation would leave a still-vulnerable, unpatchable dependency in place. `fast-xml-parser` structurally cannot fetch a DTD or external entity, so the file-read/SSRF form of CWE-611 that `libxmljs` enables is eliminated regardless of configuration; `processEntities: false` is added on top to also stop in-document entity substitution (the DoS-flavoured relative of this weakness). The query logic is rewritten from an XPath lookup (`doc.get('//order/id')`) to a plain property path (`doc.order.id`) because the replacement library returns a parsed JS object, not a DOM with XPath support - this is a mechanical consequence of the library swap, not a security control on its own.

## Behaviour changes

- **Query semantics narrowed**: the original XPath `//order/id` matches an `id` element under any `order` element anywhere in the document tree. The replacement `doc?.order?.id` only matches a top-level `<order>` element's direct `<id>` child. Reason: `fast-xml-parser` has no XPath engine; this is a mechanical consequence of the library swap, not a behavioural improvement or regression by design, but it does mean a differently-nested-but-otherwise-valid input that the old code accepted may now be treated as "missing order id" (400). If the source XML is known to always place `<order>` at the document root, this is a no-op change in practice.
- **Presence check changed from truthy to `!== undefined`**: the original `if (!orderId)` relied on `doc.get()` returning `null` when absent and a truthy `Element` object (regardless of its text content) when present, so an empty-but-present `<id>` element would still pass. A plain `if (!orderId)` against the new object property would incorrectly reject an empty-string `<id></id>` as "missing." The check was written as `orderId === undefined` instead to preserve the original "element present vs. absent" semantics exactly.
- **Response value construction**: `orderId.text()` is replaced with the parsed string value directly (`res.json({ orderId })`), with `parseTagValue: false` set on the parser so numeric-looking IDs stay strings instead of `fast-xml-parser`'s default of auto-typing them as numbers. This is a compatibility setting added specifically to keep the response shape identical to the original, not an unrelated option change.
- **Malformed-XML failure behaviour is not verified equivalent**: `libxmljs.parseXml()` throws on malformed XML (which the original code does not catch, so it would bubble to Express's default error handler as a 500). `fast-xml-parser` is more lenient and may not throw for the same malformed inputs, potentially producing a partial/empty object that falls through to the existing 400 branch instead of a 500. No exception handling was added, to keep the change scoped to the parser swap - confirm this difference with a fixture test covering malformed and empty request bodies before relying on the error path.
