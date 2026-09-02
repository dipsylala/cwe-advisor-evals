## Verdict

Real CWE-611 (XML External Entity Reference) weakness. The lxml parser is explicitly configured with `resolve_entities=True`, allowing external entity resolution on untrusted XML input from a POST request.

## Source

Untrusted XML data from `request.get_data()` at line 9, which reads the raw HTTP POST body without validation.

## Fix

Change line 11 from:

```python
parser = etree.XMLParser(resolve_entities=True)
```

to:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
```

## Explanation

The vulnerability is closed by disabling external entity resolution in the lxml parser configuration. The fix sets three hardening options: `resolve_entities=False` disables entity substitution (the primary defence), `no_network=True` prevents network access during parsing, and `load_dtd=False` prevents DTD loading from external sources. This prevents attackers from injecting XXE payloads that could read arbitrary files, perform SSRF attacks, or cause denial of service through entity expansion.

## Behaviour changes

- External entity references in XML input will no longer be resolved; entity references will expand to empty strings or be ignored depending on the XML structure.
- Network connections during XML parsing are blocked.
- External DTD references are rejected.
- The parser will successfully parse valid XML documents without external entity references (the normal case) with no functional change.
- XML documents that rely on external entity expansion will now produce different output (entities will be empty/absent rather than expanded).
