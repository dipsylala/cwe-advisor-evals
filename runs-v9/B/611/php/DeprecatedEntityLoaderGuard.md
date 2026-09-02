## Verdict

CWE-611 (Improper Restriction of XML External Entity Reference), **exploitable**. Confidence: high.

- Location: `DeprecatedEntityLoaderGuard.php:10`, `DOMDocument::loadXML($xml, LIBXML_NOENT)`.
- The `LIBXML_NOENT` flag re-enables entity substitution that libxml would otherwise leave off by default, and no other control in the file restricts DTD or external entity processing.

## Source

`$xml`, the parameter of `parse_submission()`, is populated at line 18 from `file_get_contents('php://input')` — the raw, unauthenticated HTTP request body. It is fully attacker-controlled and reaches `DOMDocument::loadXML()` at line 10 unmodified and unvalidated (no length check, schema check, or DOCTYPE rejection in between).

## Fix

Library recommendation: none. This is a configuration fix against the built-in `ext/dom` extension, not a dependency swap or version bump. The `composer.json` constraint (`php ^8.2`) already guarantees a libxml release well past 2.9.0, so no additional library is needed to get the safe default.

Vulnerable code:

```php
function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // SAST FINDING: CWE-611 (XML External Entity Reference) reported here. Sink is the next statement.
    $dom->loadXML($xml, LIBXML_NOENT);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}
```

Fixed code:

```php
function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    $dom->loadXML($xml, LIBXML_NONET);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}
```

## Explanation

`LIBXML_NOENT` explicitly turns entity substitution back on, despite its name, which is what lets a `DOCTYPE`-declared external entity in the submitted XML resolve local files or trigger outbound requests once its value is read into `title`/`body`. Since `composer.json` pins `php ^8.2`, the bundled libxml is guaranteed to be well past 2.9.0 (2012), which disables external entity substitution by default — so simply dropping the flag restores that safe default without any extra call. `LIBXML_NONET` is added in its place as the defense-in-depth step the PHP guidance calls for: it blocks network access during parsing, so a DTD or entity referencing a remote URL cannot cause the parser to make a request even under some other future misconfiguration. No call to `libxml_disable_entity_loader()` is added — that function is deprecated as of PHP 8.0 and, given the `^8.2` floor, is already a no-op on every runtime this code can execute on, so adding it would supply no protection and only introduce a deprecated call.

## Behaviour changes

- Removing `LIBXML_NOENT`: any legitimate XML input that declares and uses a custom general entity in an internal or external DTD will no longer have that entity substituted — the reference is left unexpanded (or the affected node ends up empty, depending on how `nodeValue` reads it) instead of resolving to the expanded text. The five predefined XML entities (`&amp;`, `&lt;`, `&gt;`, `&apos;`, `&quot;`) are unaffected — libxml always resolves those regardless of this flag. For a plain title/body submission format this is very unlikely to be a legitimate use case, and removing the flag is what closes the XXE, so this change is required.
- Adding `LIBXML_NONET`: blocks network access libxml would otherwise attempt while resolving external entities or DTD subsets during parsing. No effect on any document that does not reference a network resource.
- No change to the function's arguments, return value, or error handling: `loadXML()`'s existing failure behavior (returns `false` and emits a libxml warning-level error, both currently unhandled by the caller) is left exactly as it was.
