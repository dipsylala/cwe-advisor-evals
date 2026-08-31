## Verdict

exploitable (confidence: high)

CWE-79 - Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')

## Source

- `Request.Query["orderId"]` (line 10) and `Request.Query["note"]` (line 11) - both are attacker-controlled query-string values with no validation or encoding applied anywhere between read and use.
- Data flow: both values are concatenated directly into the `html` string (lines 13-17) and returned unmodified via `return Content(html, "text/html")` (line 20), which writes the string to the response body verbatim.

This is a hand-built response assembled in a controller action, not a Razor view - Razor's `@variable` auto-encoding never runs here because there is no `.cshtml` in the chain, so the sink is the raw string handed to `Content()`, not `@Html.Raw()`.

## Fix

Vulnerable code:

```csharp
string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + orderId + "</p>" +
    "<p>Note from customer: " + customerNote + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

Fixed code:

```csharp
string orderId = Request.Query["orderId"];
string customerNote = Request.Query["note"];

string html = "<html><body>" +
    "<h2>Tracking Confirmation</h2>" +
    "<p>Order: " + System.Net.WebUtility.HtmlEncode(orderId) + "</p>" +
    "<p>Note from customer: " + System.Net.WebUtility.HtmlEncode(customerNote) + "</p>" +
    "</body></html>";

return Content(html, "text/html");
```

## Explanation

Both query values are HTML-encoded with `System.Net.WebUtility.HtmlEncode()` immediately before they are concatenated into the response body, which is the prescribed pattern for hand-built HTML responses outside Razor (`Content()`/`Response.Write()`-style sinks, where `@variable` auto-encoding does not apply). Encoding converts `<`, `>`, `&`, and quote characters into their HTML entity equivalents, so an injected payload such as `<script>...</script>` or an `onerror=` attribute breakout renders as inert text in both the `<p>` body content and any attribute context, rather than being parsed as markup or script by the browser. Encoding is applied at the sink (just before concatenation into `html`), matching the guidance that output encoding be the primary defence at each rendering point rather than relying on input validation.

## Behaviour changes

Legitimate values containing `<`, `>`, `&`, or quote characters (e.g. a customer note like `Tom & Jerry's order <urgent>`) now render as their literal characters in the page instead of being interpreted as HTML - this is the intended effect of the fix, not a regression, since the prior behaviour silently misrendered or executed such input. Plain alphanumeric order IDs and notes are unaffected. No change to the response status code, content type, or control flow; `Content(html, "text/html")` keeps its existing arguments and default content encoding.
