## Verdict

Exploitable XXE injection vulnerability confirmed. Raw, untrusted XML from `req.body` flows directly to `libxmljs.parseXml()` without entity expansion controls or input validation. An attacker can craft XML with DOCTYPE entity references to read local files, trigger SSRF, or cause denial of service through entity expansion.

## Source

Line 10: `const rawOrderXml = req.body;` - HTTP request body accepted as `application/xml` (line 7) with no validation.

Data flow: HTTP POST → Express middleware (line 7 configures raw XML acceptance) → `req.body` → `libxmljs.parseXml()` (line 13, the sink).

## Fix

**Vulnerable code (line 13):**
```javascript
const doc = libxmljs.parseXml(rawOrderXml);
```

**Fixed code (replace line 13):**
```javascript
  // Reject DOCTYPE declarations in input (defense-in-depth)
  if (rawOrderXml.includes('<!DOCTYPE')) {
    return res.status(400).send('DOCTYPE not allowed');
  }

  // Parse with entity replacement disabled
  const doc = libxmljs.parseXml(rawOrderXml, { replaceEntities: false });
```

## Explanation

The fix applies two layers of defense against XXE injection:

1. **Input validation** (lines 13-15): Rejects any XML containing a DOCTYPE declaration. This is the strongest option per the guidance and stops entity injection before it reaches the parser.

2. **Secure parser configuration** (line 18): Passes `{ replaceEntities: false }` to `libxmljs.parseXml()` to prevent entity expansion. This is the current libxmljs API option (replacing the older `noent` option in legacy versions) and disables external entity resolution in the underlying libxml2 parser.

The fix preserves the sink's contract: `parseXml()` still returns a parsed XML Document object that the calling code (lines 15-20) consumes unchanged. The early rejection of DOCTYPE merely adds a validation gate before parsing begins.

**Security note:** libxmljs carries CVE-2024-34391 with no patched release. This fix hardens the parsing configuration but does not replace the dependency. A long-term remediation should consider migrating to `xml2js` (which does not implement DTD fetching at all, making it resistant to this class of XXE) or `fast-xml-parser` with `processEntities: false`.

## Behaviour changes

- Requests with XML containing DOCTYPE declarations now return HTTP 400 with message "DOCTYPE not allowed" instead of attempting to parse them.
- Valid XML without DOCTYPE declarations continues to parse and behave as before.
- External entity expansion is disabled even if DOCTYPE were allowed to reach the parser (defense-in-depth).
- No changes to the returned Document structure or downstream code logic (lines 15-20).
