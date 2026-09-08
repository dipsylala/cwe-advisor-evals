## Verdict

Confirmed. `DOMDocument::loadXML()` is called with the `LIBXML_NOENT` flag on a request body that is entirely attacker-controlled, so any DOCTYPE the client sends is parsed with entity substitution enabled.

## Source

`file_get_contents('php://input')` — the raw HTTP request body — is passed unmodified as `$xml` into `parse_submission()`.

## Fix

### File: DeprecatedEntityLoaderGuard.php
```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // Do not request entity substitution (LIBXML_NOENT) and block any
    // network-based entity/DTD retrieval as defense in depth.
    $dom->loadXML($xml, LIBXML_NONET);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

`LIBXML_NOENT` tells libxml2 to substitute entities during parsing, including general entities declared in an inline `<!DOCTYPE>` that the attacker controls end-to-end since the whole body comes from `php://input`. A `<!ENTITY xxe SYSTEM "...">` declaration combined with that flag is the classic XXE vector for local file disclosure or SSRF once the entity is referenced in `<title>`/`<body>`.

The tempting alternative fix — calling `libxml_disable_entity_loader(true)` before parsing — does nothing useful here: that function has been deprecated since PHP 8.0 and is a no-op, because PHP 8.0+ already disables the legacy external entity loader globally by default. Adding it back would only emit a deprecation notice without changing behavior, which is why it is not part of this fix.

The actual fix is to stop requesting entity substitution at all: drop `LIBXML_NOENT` from the `loadXML()` call. `DOMDocument::$resolveExternals` is already `false` by default and is left untouched, so external DTDs and external entities are never fetched. `LIBXML_NONET` is added as defense in depth, blocking any network access libxml2 would otherwise attempt while parsing, in case an older or non-default libxml2 build is ever linked. The two `getElementsByTagName()` lookups are unaffected since neither `<title>` nor `<body>` depend on entity expansion for well-formed submissions.
