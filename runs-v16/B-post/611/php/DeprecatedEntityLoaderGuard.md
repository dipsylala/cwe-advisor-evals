## Verdict

Exploitable. The data flow from untrusted input to XML parser with entity expansion enabled is complete: `file_get_contents('php://input')` on line 18 provides the XML string, which flows directly to `$dom->loadXML($xml, LIBXML_NOENT)` on line 10. The `LIBXML_NOENT` flag explicitly enables XML entity substitution, allowing an attacker to inject external entity references that read files, perform SSRF attacks, or cause DoS.

## Source

Line 18: `file_get_contents('php://input')` - untrusted XML from HTTP request body

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

The vulnerability is introduced by the `LIBXML_NOENT` flag, which enables XML entity substitution despite its misleading name. This allows external entity references in the XML to be resolved and expanded, opening the door to XXE attacks. The fix removes `LIBXML_NOENT` and adds `LIBXML_NONET` instead. Since PHP 8.2 uses libxml 2.9+ (which disabled entity substitution by default since 2012), removing the explicit `LIBXML_NOENT` flag restores the safe default. Adding `LIBXML_NONET` provides defense in depth by preventing network access during parsing, blocking XXE even if other code paths leave entity resolution enabled.

## Behaviour changes

None. The sink contract is fully preserved. `DOMDocument::loadXML()` still parses the XML string and returns void (in PHP 8.0+), and the DOM object remains populated with the parsed structure. The only functional difference is that external entities are no longer substituted, which is the intended security fix—legitimate XML documents that do not contain entity references are unaffected.
