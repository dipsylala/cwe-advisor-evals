## Verdict

Confirmed. `parse_submission()` parses attacker-controlled XML (the raw HTTP request body, `php://input`) with `DOMDocument::loadXML()` using the `LIBXML_NOENT` option. That option forces substitution of entities, including a `SYSTEM`-identified entity declared in the document's own internal DTD subset (e.g. `<!ENTITY xxe SYSTEM "file:///etc/passwd">`). Because such an entity is declared inline in the internal subset, it does not require external DTD loading to be enabled, so it is resolved regardless of PHP version or the `libxml_disable_entity_loader()` setting (which is a no-op / deprecated since PHP 8.0 and irrelevant here). An attacker can submit a crafted document whose `title`/`body` fields then contain the contents of a local file or the result of a request to an internal URL, and the response is echoed back as JSON — giving the attacker a read oracle for local files and internal network resources.

## Source

`file_get_contents('php://input')` (the raw HTTP request body) passed into `parse_submission($xml)`.

## Fix

```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // Do not pass LIBXML_NOENT: it forces substitution of entities, including
    // SYSTEM-identified entities declared in the document's own internal DTD
    // subset, which is the XXE vector even on modern PHP/libxml2 defaults.
    // LIBXML_NONET additionally blocks any network-based external entity
    // fetch as defense in depth.
    $dom->loadXML($xml, LIBXML_NONET);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

The vulnerable line is `$dom->loadXML($xml, LIBXML_NOENT)`. `LIBXML_NOENT` tells libxml2 to substitute entities during parsing. An entity does not need to come from an *external* DTD file to be dangerous: it can be declared directly in the submitted document's internal DTD subset with a `SYSTEM` identifier, e.g.

```
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data><title>&xxe;</title><body>x</body></data>
```

Because the internal subset is part of the document itself, no separate "load external DTD" flag (`LIBXML_DTDLOAD`) is required — only entity substitution (`LIBXML_NOENT`) is needed for the parser to resolve `&xxe;` to the target file's contents, which then flows out through `getElementsByTagName('title')->item(0)->nodeValue` into the JSON response.

This is unaffected by `libxml_disable_entity_loader()`: that function has been deprecated and a no-op since PHP 8.0, because libxml2 already disables loading of the *external* DTD subset by default — a separate, narrower protection that does not cover internal-subset SYSTEM entities combined with `LIBXML_NOENT`. Removing `LIBXML_NOENT` is the actual fix: without it, libxml2 does not perform entity substitution, so `&xxe;` is left as a literal, unexpanded reference in the DOM tree rather than being replaced with file or URL contents, and no DTD-declared entity — internal or external — can leak data through the parsed output. `LIBXML_NONET` is added as defense in depth to block any network-based external entity or DTD fetch attempt regardless of other flags. If entity expansion for legitimate, non-attacker-controlled entities is ever required, use a fixed allowlist of internal entities defined by the application rather than trusting entities declared in caller-supplied XML.
