## Verdict

Exploitable. The vulnerable XML parser configuration allows XXE injection through untrusted user input.

## Source

**Data flow:**
- Source: `xml_body = request.get_data()` (line 9) - untrusted XML from HTTP POST request body
- Intermediate: Parser created with `resolve_entities=True` (line 11) - explicitly enables entity resolution
- Sink: `etree.fromstring(xml_body, parser=parser)` (line 13) - parses untrusted XML with unsafe parser configuration

An attacker can craft a malicious XML payload with external entity definitions (XXE) to read files, perform SSRF attacks, or cause denial of service.

## Fix

**Vulnerable code:**
```python
parser = etree.XMLParser(resolve_entities=True)
# SAST FINDING: CWE-611 (Improper Restriction of XML External Entity Reference) reported here. Sink is the next statement.
root = etree.fromstring(xml_body, parser=parser)
```

**Fixed code:**
```python
parser = etree.XMLParser(resolve_entities=False, load_dtd=False)
# External entity resolution is disabled; XXE attacks are prevented.
root = etree.fromstring(xml_body, parser=parser)
```

## Explanation

The primary fix disables external entity resolution by setting `resolve_entities=False`, which is the documented default-unsafe value for lxml. This prevents the parser from resolving entity references defined in the XML's DTD, closing the XXE injection vector. The additional `load_dtd=False` parameter provides defense-in-depth by preventing DTD loading altogether, eliminating the attack surface even if a DTD is present in the input. Together, these settings ensure that external entity references in untrusted XML are rejected rather than expanded, preventing file disclosure and SSRF attacks.

## Behaviour changes

The parser will no longer expand external entity references. External entities defined in the DTD will remain unresolved, and references to them will expand to empty strings. This is the correct and safe behavior for a parser processing untrusted XML. The application logic does not depend on external entity expansion - it only extracts element text via `findtext()`, which correctly handles empty elements.
