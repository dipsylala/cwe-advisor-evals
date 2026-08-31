## Verdict
Confirmed XXE vulnerability. The `libxmljs.parseXml()` call parses untrusted XML without disabling external entity resolution, allowing an attacker to inject malicious DTD declarations or external entity references to read local files, perform SSRF, or cause denial of service.

## Source
Line 13: `const doc = libxmljs.parseXml(rawOrderXml);`

The `rawOrderXml` parameter comes directly from `req.body`, which accepts XML submitted by untrusted clients via the `/orders/import` POST endpoint. No validation or entity restrictions are applied before parsing.

## Fix
Pass an options object to `parseXml()` that disables external entity and DTD processing:

```javascript
const doc = libxmljs.parseXml(rawOrderXml, { noent: false, nonet: true });
```

The options:
- `noent: false` - disables substitution of external entities during parsing
- `nonet: true` - prevents network access for entity loading (blocks both file:// and http(s):// entity references)

This prevents XXE attacks by ensuring the parser will not attempt to resolve, load, or expand external entity references within the XML document.

## Explanation
XML External Entity injection attacks exploit parsers that process DTD declarations and entity references without restriction. A malicious XML document can declare external entities pointing to local files (e.g., `/etc/passwd`), internal services (SSRF), or resource-exhaustion loops (Billion Laughs attack). By disabling entity substitution and network access at the parser level, the application treats all entity references as literal text and never attempts to load external resources, eliminating the attack surface while preserving normal XML parsing for order data.
