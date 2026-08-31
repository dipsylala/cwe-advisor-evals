## Verdict

Confirmed exploitable. Reflected XSS: `Request.QueryString["ticketRef"]` reaches `Response.Write` unencoded in an HTML body context.

## Source

`Request.QueryString["ticketRef"]` (`HttpResponseWriteUnencoded.cs`, line 11) - attacker-controlled query-string parameter, assigned directly to `ticketRef` with no validation or encoding applied before use.

## Fix

Vulnerable code (line 18):

```csharp
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

Fixed code:

```csharp
using System.Net;
...
Response.Write("<p>Showing status for ticket: " + WebUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation

`ticketRef` flows straight from the query string into an HTML body fragment written via `Response.Write`, with no encoding in between, so a value like `<script>...</script>` is emitted verbatim and executes in the victim's browser. This is Web Forms/`System.Web` code, not Razor, so there is no auto-encoding to rely on; the fix wraps the tainted value in `WebUtility.HtmlEncode()` at the point it is concatenated into the markup, matching the knowledge base's guidance for `Response.Write` sinks outside Razor. `WebUtility.HtmlEncode` escapes `<`, `>`, `&`, and quotes for HTML body/text context, which is exactly where this value is rendered (a `<p>` element's text content, not an attribute or a `<script>` block), so no other encoder is needed here. The encoding is applied only at this sink; the two literal `Response.Write` calls that emit static markup are untouched.

## Behaviour changes

None for legitimate ticket references (alphanumeric/typical identifiers render identically). A `ticketRef` value containing `<`, `>`, `&`, or quote characters will now display as literal escaped text (e.g. `&lt;`) in the response instead of being interpreted as HTML/script, which is the intended effect of the fix.
