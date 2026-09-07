## Verdict

exploitable

## Source

User-supplied XML input from `req.body` in the POST request handler, which accepts raw XML bodies from trading partners without validation or entity processing restrictions.

## Fix

**Vulnerable code (line 13):**
```javascript
const doc = libxmljs.parseXml(rawOrderXml);
```

**Fixed code:**
```javascript
const express = require('express');
const { XMLParser } = require('fast-xml-parser');

const app = express();

// Accept raw XML bodies posted by trading partners for order import.
app.use(express.text({ type: 'application/xml' }));

app.post('/orders/import', (req, res) => {
  const rawOrderXml = req.body;

  // Parse XML with XXE protection: disable entity processing
  const parser = new XMLParser({
    processEntities: false
  });
  
  try {
    const doc = parser.parse(rawOrderXml);
    
    const orderId = doc?.order?.id;
    if (!orderId) {
      return res.status(400).send('missing order id');
    }

    res.json({ orderId });
  } catch (err) {
    return res.status(400).send('Invalid XML');
  }
});

module.exports = app;
```

**Library recommendation:** Replace `libxmljs` (which carries unfixed CVE-2024-34391) with `fast-xml-parser` and configure it with `processEntities: false` to prevent external entity resolution. The version must be confirmed via SCA/dependency-check tooling against current security advisories.

## Explanation

The original code uses `libxmljs`, which binds libxml2 and can resolve external entity definitions in XML documents. This allows attackers to read local files, perform SSRF attacks, or cause denial of service by crafting malicious XML with external entity references or entity expansion. The libxmljs library carries CVE-2024-34391 with no patched release, making it unsafe to use regardless of parser configuration.

The fix replaces libxmljs with `fast-xml-parser`, configured with `processEntities: false` to disable entity expansion and external entity resolution. The parser is instantiated with secure defaults before parsing untrusted input. Error handling is added to reject malformed XML gracefully. The XPath-like access pattern (`doc?.order?.id`) replaces libxmljs's `.get()` method while maintaining backward compatibility with the original logic.

## Behaviour changes

1. **Property access syntax change**: libxmljs returns an Element object with `.get()` and `.text()` methods; fast-xml-parser returns a plain JavaScript object where nested elements are accessed via dot notation and values are extracted directly (no `.text()` call needed). This is a semantic change to match fast-xml-parser's output format and is necessary when switching parsers.

2. **Error handling is now explicit**: The original code throws synchronously on parse errors; the fixed code wraps parsing in try/catch and returns a 400 status. This prevents unhandled exceptions and provides explicit error feedback.

3. **Asynchronous behavior eliminated**: Both libxmljs and fast-xml-parser parse synchronously in the fixed code, preserving the original request handler's synchronous structure.

4. **Parser instantiation moved into handler**: The XMLParser instance is created per-request rather than once at module load. This is a minor performance trade-off for clarity and to ensure security options are consistently applied.
