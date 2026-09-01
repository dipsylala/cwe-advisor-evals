## Verdict
Exploitable

## Source
Untrusted user input from `file_get_contents('php://input')` at line 18 flows directly to the vulnerable sink.

## Fix

**Vulnerable code:**
```php
$dom->loadXML($xml, LIBXML_NOENT);
```

**Fixed code:**
```php
$dom->loadXML($xml, LIBXML_NONET);
```

## Explanation

The vulnerability is caused by the `LIBXML_NOENT` flag, which enables XML entity substitution despite its misleading name. This allows an attacker to supply a malicious XML document containing external entity definitions, leading to file disclosure (reading arbitrary files on the server) or SSRF attacks. The fix removes `LIBXML_NOENT` and replaces it with `LIBXML_NONET`, which prevents network access during XML parsing as a defence-in-depth measure. Since PHP 8.2's libxml 2.9.0+ has external entity loading disabled by default, omitting `LIBXML_NOENT` ensures the secure default is preserved, while `LIBXML_NONET` blocks any attempt to access the network during entity resolution.

## Behaviour changes

- **Flag change (LIBXML_NOENT → LIBXML_NONET)**: `LIBXML_NOENT` enables entity substitution, which is the XXE vector. Removing it preserves the secure libxml default that disables external entity loading. `LIBXML_NONET` is added to prevent network access during parsing as a secondary safeguard against SSRF.
- **Return value**: Unchanged. `loadXML()` still returns a boolean indicating parse success or failure.
- **Parsing behavior**: XML is still parsed normally. External entities are no longer resolved, so entity references will expand to empty strings (or be rejected by the parser depending on configuration), and the document is processed securely.
- **Error handling**: Unchanged. Parsing errors still produce the same boolean return value.
