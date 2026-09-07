## Verdict

CONFIRMED. The vulnerability is real and fixable.

## Source

**File:** DeprecatedEntityLoaderGuard.php  
**Line:** 10  
**Vulnerable Code:**
```php
$dom->loadXML($xml, LIBXML_NOENT);
```

**Data Flow:** The XML input originates from `file_get_contents('php://input')` at line 18 (attacker-controlled request body), flows to `parse_submission()` at line 5, and reaches the vulnerable sink at line 10 where `DOMDocument::loadXML()` is called with the `LIBXML_NOENT` flag. This flag enables entity substitution, which allows XXE attacks to resolve external entities defined in malicious DTDs.

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

The fix removes the `LIBXML_NOENT` flag from `DOMDocument::loadXML()` and replaces it with `LIBXML_NONET`. The `LIBXML_NOENT` flag explicitly enables entity substitution despite the counter-intuitive name ("no entities" is the opposite of what it does), which allows external entity references to be resolved. On PHP 8.2 with a modern libxml (2.9.0+), external entity loading is disabled by default, but the presence of `LIBXML_NOENT` defeats that default protection.

The replacement flag `LIBXML_NONET` provides defense-in-depth by preventing the XML parser from making any network connections during parsing, which blocks both file disclosure via `file://` URIs and SSRF attacks via `http://` or `https://` URIs. This is a strict superset of the required protection: it closes XXE while allowing safe entity expansion from the document itself.

**Verification:** PHP syntax check passed; `DOMDocument::loadXML()` accepts both flags as valid arguments.

## Behaviour changes

**Before:** The parser enabled entity substitution when processing XML, allowing external entity definitions in the DTD to be resolved. A malicious XML payload like the following would cause the parser to attempt to read `/etc/passwd`:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**After:** The parser rejects network and file access during XML parsing. The same malicious payload is now parsed safely: external entity references fail to resolve, the entity reference expands to nothing (empty string), and the element is read as empty. The application continues to function normally with trusted XML but is protected against XXE injection attacks.

No other behavior changes. The parser still processes well-formed XML documents normally, and the return value shape and DOM traversal logic remain identical.
