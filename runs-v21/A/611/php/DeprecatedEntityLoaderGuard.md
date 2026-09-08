## Verdict

CONFIRMED — CWE-611 vulnerability. The `LIBXML_NOENT` flag enables XML entity substitution, allowing XXE attacks.

## Source

Line 10 of `DeprecatedEntityLoaderGuard.php`: `$dom->loadXML($xml, LIBXML_NOENT)` accepts user-supplied XML and enables entity substitution. An attacker can inject external entity declarations to read files, perform SSRF, or cause denial of service.

## Fix

### File: DeprecatedEntityLoaderGuard.php

```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // SAST FINDING: CWE-611 (XML External Entity Reference) reported here. Sink is the next statement.
    $dom->loadXML($xml);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

The `LIBXML_NOENT` flag enables entity substitution during XML parsing. This allows external entity references (`<!ENTITY>` declarations) to be expanded, which attackers exploit via XXE attacks. The fix removes this flag, preventing entity substitution entirely. The DOM still parses the XML structure normally — only the dangerous entity expansion behavior is disabled. This is safe for legitimate XML documents that do not require custom entity definitions.
