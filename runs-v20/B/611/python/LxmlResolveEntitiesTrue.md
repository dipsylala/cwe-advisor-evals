## Verdict

Exploitable. CWE-611 (Improper Restriction of XML External Entity Reference).

## Source

`xml_body = request.get_data()` at line 9 in `import_order()` - the raw, unvalidated HTTP POST body of the `/orders/import` Flask route. This is fully attacker-controlled.

## Fix

### File: LxmlResolveEntitiesTrue.py

```python
from flask import Flask, request, Response
from lxml import etree

app = Flask(__name__)


@app.route("/orders/import", methods=["POST"])
def import_order():
    xml_body = request.get_data()

    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(xml_body, parser=parser)

    order_id = root.findtext("orderId")
    customer_note = root.findtext("note")

    return Response(f"Imported order {order_id}: {customer_note}", mimetype="text/plain")


if __name__ == "__main__":
    app.run()
```

## Explanation

The sink at line 13, `etree.fromstring(xml_body, parser=parser)`, parses the attacker-controlled request body with a parser explicitly constructed with `resolve_entities=True` at line 11. `lxml` substitutes external and internal entities by default when this flag is set, so a request body carrying a `<!DOCTYPE>` with an external entity (e.g. one pointing at a local file via `file://` or an internal network address for SSRF) is expanded and its content is spliced into the parsed tree, from which `root.findtext("orderId")` or `root.findtext("note")` can read it back into the HTTP response. The fix changes only the `XMLParser` construction: `resolve_entities=False` stops entity substitution, which is the change that actually closes the weakness for this library, and `load_dtd=False` / `no_network=True` are set explicitly alongside it per the language guidance to make the parser's DTD and network posture unambiguous at the call site rather than relying on unstated defaults. The parsing call itself, its arguments, and the rest of the function are unchanged.

## Behaviour changes

- `resolve_entities=False` (was `True`): entity references in the XML body no longer expand. A well-formed request with no entity references parses identically. A request that relied on entity substitution to populate `orderId` or `note` will now see that reference resolve to empty text rather than expanded content - this is the intended effect for attacker-supplied entities (e.g. an XXE payload now yields an empty or unresolved field instead of leaking file contents), and per the loaded guidance no legitimate order-import payload should depend on internal entity expansion for its `orderId`/`note` values, but this is called out as a behavioural change rather than a silent one.
- `no_network=True` (was left at parser default): `lxml`'s documented default for `no_network` is already `True`, so this is a no-op that makes the setting explicit rather than a functional change.
- `load_dtd=False` (was left at parser default): `lxml`'s documented default for `load_dtd` is already `False`, so this is also a no-op made explicit, not a functional change.
- No other arguments, return values, or control flow were altered.

## Assumptions

- Python interpreter version was not provided with the finding. The language guidance notes standard-library XML parsers were hardened in CPython 3.6.8/3.7.1, but that is not relevant here since the vulnerable call is through `lxml`, whose `resolve_entities` default is unaffected by CPython version - so the fix applies regardless of interpreter version. Confidence: high (the sink and fix do not depend on the assumption).
- No SCA/library-version issue is in scope: `lxml` itself is not being replaced or upgraded, only its parser configuration at the call site, so no minimum version is asserted here.

## Verification

Ran `python -m py_compile` (Python 3.13.12) against the fixed file in an isolated scratch copy: no errors, exit code 0.
