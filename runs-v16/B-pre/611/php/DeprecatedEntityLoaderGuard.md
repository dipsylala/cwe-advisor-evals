## Verdict

Exploitable. The vulnerable code passes `LIBXML_NOENT` flag to `DOMDocument::loadXML()`, which enables entity substitution in untrusted XML input, allowing XXE attacks (file disclosure, SSRF, DoS).

## Source

Untrusted XML input: `$xml` parameter passed to `parse_submission()` (line 18: sourced from `file_get_contents('php://input')`).

## Fix

**Vulnerable code (line 10):**
```php
$dom->loadXML($xml, LIBXML_NOENT);
```

**Fixed code:**
```php
$dom->loadXML($xml, LIBXML_NONET);
```

## Explanation

The `LIBXML_NOENT` flag enables entity substitution despite its misleading name, allowing attackers to inject malicious entity definitions in XML that can read files or trigger SSRF. The fix removes this flag and replaces it with `LIBXML_NONET`, which disables network access during parsing and prevents external entity resolution as a defence-in-depth measure. Since PHP 8.2 (as specified in the code), `libxml_disable_entity_loader()` is deprecated and unnecessary because libxml 2.9.0+ disables external entity loading by default when no entity-enabling flags are passed.

## Behaviour changes

None. The fix preserves the original sink contract: `DOMDocument::loadXML()` parses and processes the XML structure, extracting element values as before. The removal of `LIBXML_NOENT` only prevents external entity resolution; legitimate XML without malicious entity definitions parses identically. The addition of `LIBXML_NONET` adds network-access hardening with no impact on parsing of local XML.
