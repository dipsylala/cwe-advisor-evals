## Verdict

Exploitable. Untrusted user input from the query parameter flows without sanitization to an HTML output sink.

## Source

`ProfileController.Welcome()` line 21: `Request.Query["nickname"].ToString()` receives untrusted input from an HTTP query parameter. This value flows through `GreetingService.BuildAndRenderBanner()` to `BannerContent.Message` and is embedded directly into an HTML string in `WelcomeBannerRenderer.Write()` line 11 without any output encoding.

## Fix

**Vulnerable code** (WelcomeBannerRenderer.cs line 11):
```csharp
string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

**Fixed code**:
```csharp
using System.Net;
// ... at the top of the file

public async Task Write(HttpResponse response, BannerContent banner)
{
    response.ContentType = "text/html";
    string html = $"<div class='welcome-banner'>Welcome back, {WebUtility.HtmlEncode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";

    await response.WriteAsync(html);
}
```

Alternatively, using `System.Text.Encodings.Web`:
```csharp
using System.Text.Encodings.Web;
// ...
string html = $"<div class='welcome-banner'>Welcome back, {HtmlEncoder.Default.Encode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

## Explanation

The vulnerability occurs because `banner.Message` (derived from untrusted user input via the query parameter "nickname") is interpolated directly into HTML without encoding. An attacker can inject malicious script tags or event handlers, for example `<img src=x onerror=alert('xss')>` or `<script>alert('xss')</script>`, which will execute in the victim's browser.

The fix applies HTML encoding to `banner.Message` using `System.Net.WebUtility.HtmlEncode()` or `System.Text.Encodings.Web.HtmlEncoder.Default.Encode()` before inserting it into the HTML string. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, etc.), preventing the injected input from being interpreted as markup or script.

## Behaviour changes

None. HTML encoding preserves the semantic meaning of the original text - legitimate content containing special characters (e.g., "Tom & Jerry's Place" or mathematical expressions) will display correctly with entities decoded back to their original characters by the browser. The date format in `{banner.RequestedAt:u}` remains unchanged and is not affected.

