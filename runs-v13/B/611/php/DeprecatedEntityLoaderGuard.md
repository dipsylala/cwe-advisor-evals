## Verdict

Exploitable. The `LIBXML_NOENT` flag explicitly enables entity substitution in the DOMDocument parser, directly causing the XXE weakness. Untrusted XML from `php://input` flows directly to the sink at line 10 without sanitization.

## Source

**Data flow:**
- Source: Line 18 `file_get_contents('php://input')` — untrusted user-supplied XML
- Intermediate: Line 5 parameter `$xml: string` — passed directly to parser
- Sink: Line 10 `$dom->loadXML($xml, LIBXML_NOENT)` — parses XML with entity substitution enabled

The `LIBXML_NOENT` flag explicitly requests the parser to expand XML entities, overriding libxml's default safe behavior (entity substitution disabled since libxml 2.9.0). An attacker can embed `<!DOCTYPE>` with external entity definitions to read files, perform SSRF, or cause DoS.

## Fix

**Original (vulnerable):**
```php
$dom->loadXML($xml, LIBXML_NOENT);
```

**Fixed:**
```php
$dom->loadXML($xml, LIBXML_NONET);
```

Rationale: Remove `LIBXML_NOENT` (which enables the vulnerability) and replace with `LIBXML_NONET` (which prevents network access during parsing as defense in depth). Since the codebase targets PHP 8.2, no explicit `libxml_disable_entity_loader()` call is needed—libxml 2.9+ already disables external entity loading by default, and PHP 8.0+ deprecated that function. The single-flag change is sufficient.

## Explanation

The vulnerability stems from the `LIBXML_NOENT` flag, which explicitly instructs the parser to substitute entity definitions. This contradicts the default secure behavior of modern libxml and reopens XXE exposure. The fix removes this dangerous flag entirely and substitutes `LIBXML_NONET` to prevent the parser from making network requests during parsing (a secondary defense layer). This combination ensures external entities are neither expanded nor fetched, regardless of their presence in the XML document. The parse will complete, but any external entity reference will be left unexpanded—which is the safe default behavior. The caller already handles missing elements gracefully via the null-coalescing operator `?->`, so silently empty expansion produces correct behavior.

## Behaviour changes

**Parsing succeeds without changes:**
- Documents without entity definitions: unchanged behavior
- Documents with entity definitions: external entities are no longer expanded (they remain as entity references or empty strings)
- Network access: disabled during parsing even if a malicious XML document attempts to fetch external DTDs

**No breaking changes to the current application logic:**
- Extracted values (`title` and `body` elements) unaffected when input is well-formed XML without malicious entities
- Error handling unchanged — invalid XML still triggers DOMDocument warnings but does not throw exceptions
- Return structure unchanged — same array with `title` and `body` keys
