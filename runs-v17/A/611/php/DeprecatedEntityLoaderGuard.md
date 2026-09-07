## Verdict

CONFIRMED: The code uses `LIBXML_NOENT` flag with `DOMDocument::loadXML()`, which enables XML entity expansion. This allows attackers to supply XML containing external entity declarations that reference arbitrary files or trigger SSRF attacks.

## Source

File: DeprecatedEntityLoaderGuard.php, line 10

```php
$dom->loadXML($xml, LIBXML_NOENT);
```

The `LIBXML_NOENT` flag enables entity substitution, which is the vector for XXE attacks. When an attacker-controlled XML string is parsed, malicious external entity declarations are expanded, potentially exposing sensitive files or allowing network-based attacks.

## Fix

### File: DeprecatedEntityLoaderGuard.php

```php
<?php

// composer.json: "require": { "php": "^8.2" }

function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // SAST FINDING: CWE-611 (XML External Entity Reference) reported here. Sink is the next statement.
    $dom->loadXML($xml, LIBXML_NONET);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

The fix removes the `LIBXML_NOENT` flag, which was enabling entity expansion, and replaces it with `LIBXML_NONET`. This prevents external entity processing in two ways:

1. **Removing `LIBXML_NOENT`** stops automatic entity substitution, which is the primary XXE vulnerability. Modern PHP does not expand entities by default when this flag is absent.

2. **Adding `LIBXML_NONET`** prevents the XML parser from accessing network resources, blocking SSRF-based XXE attacks even if entity expansion were somehow enabled through another path.

Together, these changes eliminate XXE attack vectors while maintaining normal XML parsing for legitimate documents that do not contain external entity references.
