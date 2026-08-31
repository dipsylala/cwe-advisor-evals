## Verdict

CONFIRMED - CWE-611 XXE injection vulnerability in libxmljs parser configuration.

## Source

User-supplied XML from HTTP POST body (`req.body` at line 10) flows directly to the XML parser without entity processing restrictions.

## Fix

```javascript
const doc = libxmljs.parseXml(rawOrderXml, {
  replaceEntities: false,
  dtdload: false,
  dtdvalid: false,
  noent: false
});
```

Disable external entity processing and DTD loading by passing security options to `libxmljs.parseXml()`. The options prevent the parser from:
- Replacing entity references with their definitions (`replaceEntities: false`)
- Loading external DTDs (`dtdload: false`)
- Validating against DTDs (`dtdvalid: false`)
- Resolving external entities (`noent: false`)

## Explanation

The vulnerability occurs because `libxmljs.parseXml()` is called with default options that allow XML external entity resolution. An attacker can craft XML with DOCTYPE declarations and external entity references (e.g., pointing to `/etc/passwd` or internal services) to extract sensitive data or perform server-side request forgery attacks.

The fix disables entity substitution and external DTD loading through parser configuration options. This prevents the parser from resolving external entities, blocking XXE exploitation vectors.

**Note on library status**: libxmljs carries unfixed security advisories (CVE-2024-34391). For new projects, prefer `xml2js` (which does not implement DTD fetching) or `fast-xml-parser` with `processEntities: false`. If libxmljs is already a project dependency, apply these parser settings as a configuration-level mitigation and plan to migrate to a maintained alternative.

## Behaviour changes

- External entity references in XML input will no longer be resolved
- DTD processing is disabled
- Parser will reject XML containing DOCTYPE declarations that reference external resources
- Parsing may fail with stricter error handling for malformed DOCTYPE declarations
- No impact on normal XML parsing of well-formed documents without external entity references
