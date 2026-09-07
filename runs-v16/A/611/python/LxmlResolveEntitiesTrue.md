## Verdict

True Positive. The parser is configured with `resolve_entities=True`, which enables external entity resolution and exposes the application to XXE attacks.

## Source

```python
parser = etree.XMLParser(resolve_entities=True)
root = etree.fromstring(xml_body, parser=parser)
```

Line 11 creates a parser that resolves external entities, and line 13 parses untrusted XML from the HTTP request body with this unsafe parser.

## Fix

Disable external entity resolution by setting `resolve_entities=False`:

```python
parser = etree.XMLParser(resolve_entities=False)
root = etree.fromstring(xml_body, parser=parser)
```

Optionally, for defense-in-depth, also disable DTD processing to prevent other XML-based attacks:

```python
parser = etree.XMLParser(resolve_entities=False, remove_blank_text=False, no_network=True)
root = etree.fromstring(xml_body, parser=parser)
```

## Explanation

XXE (XML External Entity) injection occurs when an XML parser processes external entity references from untrusted input. With `resolve_entities=True`, lxml will attempt to fetch and load external entities, allowing an attacker to:

- Read local files by defining entities that reference file:// URIs
- Perform server-side request forgery (SSRF) by triggering HTTP requests to internal or external systems
- Cause denial of service through billion laughs or other entity expansion attacks

Setting `resolve_entities=False` disables entity resolution entirely. The `no_network=True` parameter provides additional hardening by preventing any network access during parsing, and `remove_blank_text=False` preserves the parser's default text handling. This ensures the parser only processes the XML structure without resolving external references.
