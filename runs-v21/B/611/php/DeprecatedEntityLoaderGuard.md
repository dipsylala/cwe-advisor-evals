## Verdict

Confirmed. The finding is exploitable. Line 10 passes `LIBXML_NOENT` to `loadXML()`, which enables entity substitution and allows XXE injection attacks against untrusted XML from the HTTP request body (line 18).

## Source

Line 18: `file_get_contents('php://input')` - reads untrusted XML directly from the HTTP request body.

## Fix

The fix is to remove the `LIBXML_NOENT` flag and add `LIBXML_NONET` as defense in depth to prevent network access during parsing.

### File: DeprecatedEntityLoaderGuard.php

```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
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

The fix removes `LIBXML_NOENT`, which was enabling entity substitution despite its misleading name. The flag name reads as "no entities" but does the opposite—it activates entity substitution and reopens XXE injection. By removing it, the parser returns to its default safe mode (external entity loading disabled by libxml 2.9.0+). The added `LIBXML_NONET` flag provides defense in depth by preventing network access during parsing, which blocks SSRF and external DTD loading attacks even if the parser configuration were to drift. For PHP 8.2, this is the correct approach; `libxml_disable_entity_loader()` is deprecated in PHP 8.0+ and has nothing to do on modern libxml versions.

## Behaviour changes

- External entity references in XML input are now rejected instead of resolved, so malicious or missing entity definitions produce empty or parse-error elements rather than file content or network requests.
- Network access during XML parsing is blocked.
- DTD loading is not explicitly disabled (but external entities are blocked, which closes the primary XXE vector).
- Parsing that depends on entity substitution will fail. This is not a realistic concern for typical XML input, and the trade-off is correct: silent XXE vulnerabilities are worse than rejecting edge-case valid documents.
