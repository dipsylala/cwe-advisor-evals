## Verdict

Reported as CWE-611 (XXE), but as written this is not exploitable for external-entity disclosure or SSRF under the stated environment (`php: ^8.2`). Since libxml2 2.9.0 / PHP 8.0, the external entity resolver is disabled unconditionally at the library level — `libxml_disable_entity_loader()` is a deprecated no-op precisely because there is no longer a way to re-enable external resolution. `LIBXML_NOENT` only controls substitution of entities that have already been resolved; it does not itself cause `SYSTEM`/`PUBLIC` identifiers to be fetched. A payload like `<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>` will not disclose file contents or reach an attacker-controlled URL on this stack — the entity reference resolves to an empty value rather than the external resource.

That said, the code relies entirely on an implicit, version-dependent default rather than an explicit, self-documenting configuration, and `LIBXML_NOENT` still permits *internal* general-entity substitution (recursive self-referencing entities defined wholly inside the document's own DOCTYPE), which is a separate exponential-expansion (billion-laughs / entity-bomb) denial-of-service risk that PHP 8's external-entity default does nothing to prevent. The fix below removes the unnecessary flag and makes the safe posture explicit rather than incidental.

## Source

`file_get_contents('php://input')` (raw HTTP request body) passed directly into `parse_submission()`, reaching `DOMDocument::loadXML()` at line 10 unsanitized.

## Fix

```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
    if (stripos($xml, '<!DOCTYPE') !== false) {
        throw new InvalidArgumentException('Document type declarations are not allowed.');
    }

    $dom = new DOMDocument();
    $dom->loadXML($xml, LIBXML_NONET);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

Two changes, both defense-in-depth rather than closing an active external-entity hole (which PHP 8.2 already closes by default):

- **Dropped `LIBXML_NOENT`.** This request body only needs `title`/`body` text nodes; nothing in that shape requires entity substitution. Removing the flag restores `DOMDocument`'s default `substituteEntities = false`, which is the setting that actually stops the internal-entity expansion (billion-laughs) DoS vector `LIBXML_NOENT` leaves open — that vector doesn't depend on external resolution at all, so it survives PHP 8's XXE-specific default fix.
- **Added an explicit DOCTYPE rejection and `LIBXML_NONET`.** A JSON-style title/body submission has no legitimate reason to carry a document type declaration. Rejecting it outright removes the whole entity-declaration mechanism from the attack surface rather than depending on libxml2's current default behavior remaining unchanged in some future runtime. `LIBXML_NONET` is added so the network-blocking behavior is stated in the code itself instead of left implicit, in case this parsing logic is ever copied into a context using a different XML extension or an older/patched libxml2 build where the default isn't guaranteed.

Verify by re-running the original SAST payload (`<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x><title>&xxe;</title></x>`) and confirming the request now throws `InvalidArgumentException` instead of parsing, plus a regression test with a well-formed `<x><title>...</title><body>...</body></x>` payload confirming normal submissions still decode correctly.
