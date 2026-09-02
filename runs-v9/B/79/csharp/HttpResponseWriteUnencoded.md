## Verdict

**Exploitable** (confidence: high)

- CWE ID: CWE-79
- Location: `HttpResponseWriteUnencoded.cs`, line 18 (sink)
- Source: `Request.QueryString["ticketRef"]` (line 11) - attacker-controlled query-string parameter, read with no validation or encoding.
- Sink: `Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");` (line 18) - `ticketRef` is concatenated directly into an HTML response body.

## Source

`Request.QueryString["ticketRef"]`, assigned to `ticketRef` on line 11, flows unmodified (no validation, no encoding, no intervening transformation) into the `Response.Write` call on line 18. This is a classic reflected XSS pattern: a value an attacker controls via the URL is echoed straight into the page. A request such as `?ticketRef=<script>alert(document.cookie)</script>` results in the script tag being written verbatim into the HTML body and executed in the victim's browser.

## Fix

Vulnerable code:

```csharp
string ticketRef = Request.QueryString["ticketRef"];

Response.ContentType = "text/html";
Response.Write("<html><body>");
Response.Write("<h2>Support Ticket Lookup</h2>");

// SAST FINDING: CWE-79 reported here. Sink is the next statement.
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");

Response.Write("</body></html>");
```

Fixed code:

```csharp
using System.Net;
// ...

string ticketRef = Request.QueryString["ticketRef"];

Response.ContentType = "text/html";
Response.Write("<html><body>");
Response.Write("<h2>Support Ticket Lookup</h2>");

Response.Write("<p>Showing status for ticket: " + WebUtility.HtmlEncode(ticketRef) + "</p>");

Response.Write("</body></html>");
```

## Explanation

This is Web Forms / `System.Web` code (`Response.Write` on a `System.Web.UI.Page`), so Razor's automatic `@variable` encoding is not available; the knowledge base's guidance for this sink is to encode explicitly with `WebUtility.HtmlEncode()`. Wrapping `ticketRef` in `WebUtility.HtmlEncode()` before concatenation converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents, so any markup or script the attacker supplies is rendered as inert text inside the `<p>` element rather than being parsed as HTML/JavaScript by the browser. The encoding is applied at the point of output (the sink), which is correct per the guidance's context-aware, encode-at-each-sink principle - the value is only ever rendered into a single context here (HTML body text), so a single `HtmlEncode` call is sufficient; no `<script>` block, attribute, or URL context is involved in this code path.

`WebUtility.HtmlEncode()` returns `null` unchanged when passed `null`, matching the behaviour of an unset `ticketRef` (`Request.QueryString["ticketRef"]` returns `null` when the parameter is absent) - the original code would have concatenated the literal string `"" ` (empty, since string concatenation with `null` produces an empty substring) in that case, and the fixed code produces the same empty substring, so the no-parameter case is unaffected.

## Behaviour changes

None. `WebUtility.HtmlEncode()` only escapes markup-significant characters (`<`, `>`, `&`, `"`, `'`); it does not alter, truncate, or reject any other content in `ticketRef`, so a legitimate ticket reference (e.g. alphanumeric IDs) renders identically before and after the fix. The `Response.Write` call's other arguments, its void return, and the surrounding calls are all unchanged - only the single tainted substring is encoded.
