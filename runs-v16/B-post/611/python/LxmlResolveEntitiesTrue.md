## Verdict

CWE-611 confirmed. The XML parser is configured with `resolve_entities=True`, which allows lxml to expand external entity definitions in untrusted XML input. An attacker can exploit this to read files, perform SSRF attacks, or trigger denial-of-service.

## Source

The vulnerability is in line 11 of `LxmlResolveEntitiesTrue.py`:

```python
parser = etree.XMLParser(resolve_entities=True)
```

The parser is constructed with entity resolution enabled and passed to `etree.fromstring()` at line 13, which processes untrusted XML from `request.get_data()` (line 9).

## Fix

Change the XMLParser instantiation to disable external entity resolution:

**Vulnerable code:**
```python
parser = etree.XMLParser(resolve_entities=True)
# VULNERABLE: resolve_entities=True allows XXE attacks
root = etree.fromstring(xml_body, parser=parser)
```

**Fixed code:**
```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
root = etree.fromstring(xml_body, parser=parser)
```

## Explanation

The fix disables external entity expansion by setting `resolve_entities=False` on the lxml parser instance. This is the primary defence against XXE injection in lxml, which unlike the Python standard library still resolves entities by default.

The additional parameters `no_network=True` and `load_dtd=False` provide defence-in-depth: `no_network` prevents network access during entity resolution (redundant when entities are disabled but prevents misconfiguration if resolve_entities is later changed), and `load_dtd=False` prevents loading external DTD files entirely.

This fix preserves the existing behavior of the application - `etree.fromstring()` still returns an Element object used by the subsequent `.findtext()` calls. The parser configuration change blocks only the unsafe entity resolution, not the parsing itself.

## Behaviour changes

External entity references in XML input will no longer be expanded. If an external entity is referenced in the XML, the parser will leave the reference unresolved (the element will be empty). No exception is thrown; parsing succeeds with the empty value. Legitimate applications that require external entity resolution would need different logic and should document the requirement before enabling `resolve_entities=True` with strict input validation.
