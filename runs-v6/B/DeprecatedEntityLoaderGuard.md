## Verdict

- **CWE-611** (Improper Restriction of XML External Entity Reference)
- **Location:** `DeprecatedEntityLoaderGuard.php:10`, `DOMDocument::loadXML()`
- **Verdict:** exploitable
- **Confidence:** high
- **Assumptions:** `composer.json` pins `"php": "^8.2"`, so the fix targets PHP 8.2/8.3 behavior. `LIBXML_NO_XXE` (PHP 8.4+/libxml 2.13+) is not assumed available since the manifest does not guarantee that floor.

## Source

- **Source:** `file_get_contents('php://input')` (line 18) - the raw, unauthenticated HTTP request body, fully attacker-controlled.
- **Flow:** the raw body is passed directly as `$xml` into `parse_submission()` with no validation, then into `$dom->loadXML($xml, LIBXML_NOENT)` at line 10.
- **Sink:** `DOMDocument::loadXML()` called with the `LIBXML_NOENT` flag.

Since libxml 2.9.0, entity substitution is off by default, which would normally make this call safe. `LIBXML_NOENT` explicitly re-enables entity substitution despite its name, reopening the parser to `<!ENTITY>`-based file disclosure and SSRF via any `<!DOCTYPE>` the attacker includes in the submitted XML.

## Fix

No third-party library is involved; `DOMDocument` is a PHP built-in, so no dependency/version recommendation applies.

**Vulnerable code:**

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

**Fixed code:**

```php
function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // Omit LIBXML_NOENT so libxml's default (entity substitution off since 2.9.0)
    // applies, and pass LIBXML_NONET as defense-in-depth against network-borne
    // external entities/DTDs.
    $dom->loadXML($xml, LIBXML_NONET);

    // This submission format has no legitimate use for a DTD; reject the document
    // outright rather than relying solely on entity-resolution being disabled.
    if ($dom->doctype !== null) {
        throw new \RuntimeException('XML submissions with a DOCTYPE are not permitted');
    }

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}
```

Note: `libxml_disable_entity_loader(true)` is not added. On PHP 8.0+ it is deprecated and a no-op - libxml 2.9+ already disables external entity loading by default absent `LIBXML_NOENT`/`LIBXML_DTDLOAD`/`LIBXML_DTDVALID` - so calling it here would only emit a deprecation notice without adding protection.

## Explanation

The `LIBXML_NOENT` flag was the entire vulnerability: it turns on entity substitution, overriding libxml's safe-by-default posture and letting an attacker-supplied `<!DOCTYPE>` with an external or internal `<!ENTITY>` get expanded into the parsed document (and, by extension, into `title`/`body`), enabling file disclosure or SSRF. Dropping the flag restores the libxml 2.9+ default of leaving external entities unresolved. `LIBXML_NONET` is added as defense-in-depth so no network fetch can occur during parsing even if a future code change reintroduces an entity-related flag. The `doctype !== null` check is the strongest layer: this endpoint only expects `title`/`body` elements, so any document declaring a DTD at all is rejected outright rather than trusting flag-based entity suppression alone.

## Behaviour changes

- **`LIBXML_NOENT` removed:** any internal `<!ENTITY>` reference previously expanded into element text will no longer be substituted (it was never legitimate for this submission format, only exploitable). No effect on documents without a DTD.
- **`LIBXML_NONET` added:** parsing a document that requires a network-fetched external DTD/entity now fails instead of fetching it. No effect on well-formed `title`/`body` submissions.
- **New `doctype !== null` rejection:** any submission containing a `<!DOCTYPE>` declaration - benign or not - now throws `RuntimeException` instead of being parsed. Previously such documents were parsed (and, with `LIBXML_NOENT`, had entities expanded). This is a functional change for any legitimate caller that was relying on DTDs; given the endpoint only reads `title`/`body`, none is expected, but the caller should confirm no legitimate client sends a DOCTYPE before deploying this check, or catch the exception to return a 4xx response instead of letting it propagate as an unhandled error.
- `DOMDocument::loadXML()`'s existing failure behavior (returns `false` on a malformed document, with the result silently coerced via `?->` to empty strings) is unchanged - this was a pre-existing gap, not introduced by this fix.
