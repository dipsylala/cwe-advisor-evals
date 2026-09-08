## Verdict

CWE-611 Improper Restriction of XML External Entity Reference is confirmed. The XMLParser is configured with `resolve_entities=True`, which enables the resolution of external entities from untrusted XML input. This allows attackers to read arbitrary files, perform SSRF attacks, or trigger denial-of-service attacks.

## Source

```python
parser = etree.XMLParser(resolve_entities=True)
root = etree.fromstring(xml_body, parser=parser)
```

The vulnerability exists because `resolve_entities=True` permits lxml to resolve external entity references in the XML document. When combined with untrusted user input via `request.get_data()`, an attacker can craft malicious XML that references external files or systems.

## Fix

### File: LxmlResolveEntitiesTrue.py

```python
from flask import Flask, request, Response
from lxml import etree

app = Flask(__name__)


@app.route("/orders/import", methods=["POST"])
def import_order():
    xml_body = request.get_data()

    parser = etree.XMLParser(resolve_entities=False)
    root = etree.fromstring(xml_body, parser=parser)

    order_id = root.findtext("orderId")
    customer_note = root.findtext("note")

    return Response(f"Imported order {order_id}: {customer_note}", mimetype="text/plain")


if __name__ == "__main__":
    app.run()
```

## Explanation

The fix disables external entity resolution by setting `resolve_entities=False` in the XMLParser constructor. This is the secure default and prevents lxml from processing external entity declarations in the XML.

With `resolve_entities=False`:
- External DTD references are not loaded
- XML external entity expansion attacks are blocked
- Local file disclosure via XXE is prevented
- The parser still functions normally for well-formed XML documents that do not rely on external entities

This change closes the XXE attack surface while maintaining full functionality for legitimate XML parsing operations.
