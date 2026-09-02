## Verdict

The finding is valid. The code explicitly passes `LIBXML_NOENT` to `DOMDocument::loadXML()`, enabling entity substitution despite its misleading name. This creates an XXE vulnerability allowing attackers to read arbitrary files, perform SSRF attacks, or cause denial of service through maliciously crafted XML entity declarations.

## Source

User-supplied XML from `php://input` is read by `file_get_contents()` and passed as the `$xml` parameter to `parse_submission()`, flowing directly to the vulnerable sink.

## Fix

```php
function parse_submission(string $xml): array
{
    $dom = new DOMDocument();

    // FIXED: Removed LIBXML_NOENT, added LIBXML_NONET for defense-in-depth
    $dom->loadXML($xml, LIBXML_NONET);

    $title = $dom->getElementsByTagName('title')->item(0)?->nodeValue ?? '';
    $body = $dom->getElementsByTagName('body')->item(0)?->nodeValue ?? '';

    return ['title' => $title, 'body' => $body];
}

$result = parse_submission(file_get_contents('php://input'));
echo json_encode($result);
```

## Explanation

`LIBXML_NOENT` is a misleading flag name that actually enables entity substitution, activating XXE vulnerability. Removing it restores libxml's default (since version 2.9.0, 2012) which disables external entity loading. The fix applies the safe pattern from PHP language guidance: omit entity-expansion flags and instead use `LIBXML_NONET` for defense-in-depth to block network access during parsing. Since the codebase targets PHP 8.2, `libxml_disable_entity_loader()` is deprecated and unnecessary—the secure default is already active without explicit calls.

## Behaviour changes

- External entity declarations in XML input are ignored; references to them expand to empty content
- Attacker-supplied XML containing `<!ENTITY>` definitions no longer produces file disclosure or SSRF
- XML parsing succeeds on well-formed documents without entity expansion
- Network access is blocked during parsing (`LIBXML_NONET`), closing potential SSRF vectors
- Elements referencing undefined entities remain empty (unchanged from current behavior)
