## Verdict

Exploitable. Confidence: high.

- cwe_id: CWE-79 (Improper Neutralization of Input During Web Page Generation, Cross-Site Scripting)
- location: `RazorRawConcatOutput.cs`, line 20 (`return Content(html, "text/html");`)

## Source

`Request.Query["orderId"]` (line 10) and `Request.Query["note"]` (line 11) - both are raw HTTP query-string values, fully attacker-controlled, with no validation or encoding applied anywhere between the source and the sink.

## Fix

### File: RazorRawConcatOutput.cs

```csharp
using System.Net;
using Microsoft.AspNetCore.Mvc;

namespace OrderPortal.Controllers
{
    public class TrackingController : Controller
    {
        [HttpGet("/tracking/confirm")]
        public IActionResult Confirm()
        {
            string orderId = Request.Query["orderId"];
            string customerNote = Request.Query["note"];

            string html = "<html><body>" +
                "<h2>Tracking Confirmation</h2>" +
                "<p>Order: " + WebUtility.HtmlEncode(orderId) + "</p>" +
                "<p>Note from customer: " + WebUtility.HtmlEncode(customerNote) + "</p>" +
                "</body></html>";

            // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
            return Content(html, "text/html");
        }
    }
}
```

## Explanation

Both untrusted query values are concatenated straight into an HTML string that is returned via `Content(html, "text/html")`, so any HTML/script markup in `orderId` or `note` is sent to the browser verbatim and executes in the victim's session - classic reflected XSS with two independent injection points on the same response. The action builds its own HTML string outside the Razor view engine (it returns `ContentResult`, not a `View()` result), so Razor's automatic `@variable` encoding is not in play here; per the loaded C# guidance, the correct sink-side control in this situation is explicit encoding with `System.Net.WebUtility.HtmlEncode()`, part of the base class library (`System.Net`) and already used for this exact "outside Razor" case in the guidance. Wrapping both `orderId` and `customerNote` with `WebUtility.HtmlEncode()` at the point they are concatenated into the HTML body converts `<`, `>`, `&`, `"` and `'` into their HTML entity equivalents, so injected markup renders as inert text instead of being parsed as tags or attributes, while ordinary alphanumeric order IDs and notes are unaffected.

## Behaviour changes

- Query values containing `<`, `>`, `&`, `"`, or `'` now render as their literal HTML-entity text (e.g. `&lt;`) in the page body instead of being interpreted as markup. This is the intended effect of the fix and is the only behavioural difference; the response's content type (`text/html`), status code, and success-path structure are unchanged, and no argument, return value, or discarded output differs from the original `Content(...)` call.
- No other change: same two sources, same sink, same call signature.

## Verification

Copied the fixed file into a scratch ASP.NET Core project (`Microsoft.NET.Sdk.Web`, target `net10.0`, referencing only the shared framework - no extra packages) alongside a minimal `Program.cs` calling `AddControllers()`/`MapControllers()`, and ran `dotnet build`. Build succeeded with 0 errors, 0 warnings, confirming `WebUtility.HtmlEncode` resolves against `System.Net` and the edited method compiles unchanged otherwise. No unit tests exist for this fixture to run.
