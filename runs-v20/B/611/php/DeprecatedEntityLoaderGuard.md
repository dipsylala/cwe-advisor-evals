## Verdict

exploitable

- **cwe_id**: CWE-611
- **location**: `DeprecatedEntityLoaderGuard.php`, line 10 (`$dom->loadXML($xml, LIBXML_NOENT);`)
- **confidence**: high
- **library_recommendation**: none needed - the fix is a parser configuration change to PHP's built-in `DOMDocument`/libxml bindings, not a third-party dependency

## Source

`file_get_contents('php://input')` (line 18) - the raw, fully attacker-controlled HTTP request body, passed directly into `parse_submission()` with no validation.

## Fix

### File: DeprecatedEntityLoaderGuard.php

```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    $dom->loadXML($xml, LIBXML_NONET);

    if ($dom->doctype !== null) {
        throw new InvalidArgumentException('XML submissions may not declare a DOCTYPE.');
    }

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

The sink was `DOMDocument::loadXML($xml, LIBXML_NOENT)`. `LIBXML_NOENT` enables entity substitution - despite the name, it is the flag that turns this vulnerability on - and on this codebase's own composer-declared PHP (`^8.2`, confirmed against a local PHP 8.5/libxml 2.11.9 install) it overrides libxml's post-2.9.0 default of leaving external entities unresolved. A payload declaring `<!DOCTYPE submission [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>` with `&xxe;` in `<title>` was confirmed to disclose the target file's contents through the returned `title` field against the original code. The fix removes `LIBXML_NOENT` (the parser no longer substitutes any entity, internal or external, closing the disclosure and SSRF path) and adds `LIBXML_NONET` as defense-in-depth against any parser-initiated network access. It also rejects the document outright whenever `DOMDocument::$doctype` is non-null: a title/body submission has no legitimate use for a DTD, and per the loaded PHP guidance this is the stronger response - it fails the request instead of silently returning an empty field, which is what merely dropping `LIBXML_NOENT` alone would do (confirmed: with the flag removed but no doctype check, the same payload parses successfully with `title` silently emptied rather than the request being rejected). `libxml_disable_entity_loader()` was not added, per the loaded guidance: it is a no-op on PHP 8.0+ and this project's floor is 8.2.

## Behaviour changes

- **Removed `LIBXML_NOENT`**: entity references (both internal and external) are no longer substituted during parsing; this is the mechanism that closes the weakness and has no legitimate use in this handler, which only ever reads plain element text.
- **Added `LIBXML_NONET`**: blocks any network access libxml might otherwise attempt during parsing (defense-in-depth per the loaded guidance's Remediation Steps); no legitimate submission in this handler needs network-fetched XML content, so this has no effect on valid input.
- **Added a `DOMDocument::$doctype` check that throws `InvalidArgumentException`**: any XML submission declaring a DOCTYPE is now rejected outright (uncaught, this surfaces as a request failure) rather than parsed with entities silently left unexpanded. This is a behavior change for any caller that was previously sending a DTD-bearing document expecting it to be silently accepted - the loaded guidance treats that as having no legitimate use here, since the handler only extracts `title`/`body` text.
- Return type, return value shape (`['title' => ..., 'body' => ...]`), and the calling code (lines 18-19) are unchanged.
- **Verification**: `php -l` on the fixed file reported "No syntax errors detected". Functional testing against a scratch copy confirmed: (1) a benign `<submission><title>Hello</title><body>World</body></submission>` document still parses to `['title' => 'Hello', 'body' => 'World']`; (2) the XXE payload above is rejected with `InvalidArgumentException: XML submissions may not declare a DOCTYPE.` before any entity resolution occurs; (3) the original, unfixed code was independently confirmed exploitable against the same payload, returning the contents of the target file in `title`.
