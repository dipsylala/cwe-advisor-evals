## Verdict

Confirmed. The parser at line 11 is explicitly configured with `resolve_entities=True`, and the attacker-controlled request body (`request.get_data()`) is parsed with it at line 13. A crafted body defining an external entity (e.g. via a `DOCTYPE` with a `SYSTEM` or `PUBLIC` identifier) will have that entity resolved and its content substituted into the tree, where it becomes reachable through `root.findtext(...)` and is reflected back in the HTTP response. This allows local file disclosure (`file://`) and, depending on network reachability, SSRF via other URI schemes.

## Source

`xml_body = request.get_data()` (line 9) - the raw, unvalidated HTTP request body of a POST to `/orders/import`, fully attacker-controlled.

## Fix

```python
from flask import Flask, request, Response
from lxml import etree

app = Flask(__name__)


@app.route("/orders/import", methods=["POST"])
def import_order():
    xml_body = request.get_data()

    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    root = etree.fromstring(xml_body, parser=parser)

    order_id = root.findtext("orderId")
    customer_note = root.findtext("note")

    return Response(f"Imported order {order_id}: {customer_note}", mimetype="text/plain")


if __name__ == "__main__":
    app.run()
```

## Explanation

The only change needed is the `etree.XMLParser` construction. Setting `resolve_entities=False` (lxml's own default, overridden here) instructs libxml2 to leave external and internal general entity references unresolved rather than substituting their referenced content into the parsed tree - an unresolved entity reference simply yields no expansion, so `file://` or `http://` payloads embedded via a `DOCTYPE`/`ENTITY` declaration are never fetched or inlined. `no_network=True` is added as defense in depth so that even if a code path elsewhere ends up resolving entities, libxml2 is blocked from making outbound network requests for external subsets or entities. `huge_tree=False` (the default) is kept explicit to avoid disabling libxml2's built-in protections against maliciously deep/large trees, which is a related hardening concern for the same parser object.

No other part of the flow needs to change: `etree.fromstring` is still the correct API for parsing a raw XML byte string, and `root.findtext` remains safe once the parser itself no longer expands entities - there is no remaining sink that needs separate sanitization. If the application's XML schema has no legitimate need for a DOCTYPE at all, an additional robust option is to reject any document containing one before parsing (e.g. check for `<!DOCTYPE` or use `resolve_entities=False` together with rejecting `parser.error_log` entries related to DTD), but disabling entity resolution alone closes the XXE vector demonstrated by this finding.
