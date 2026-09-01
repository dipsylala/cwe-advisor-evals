## Verdict

Confirmed exploitable XSS vulnerability. User-supplied `nickname` from the query string flows through ProfileController → GreetingService → WelcomeBannerRenderer without encoding and is rendered directly into HTML via string interpolation, allowing attacker-injected scripts to execute in the victim's browser.

## Source

Query parameter `nickname` extracted at ProfileController line 21:
```csharp
string nickname = Request.Query["nickname"].ToString();
```

No validation or encoding is applied to this untrusted input before it is propagated through GreetingService.BuildAndRenderBanner() and into WelcomeBannerRenderer.Write().

## Fix

**File: WelcomeBannerRenderer.cs**

Add the required using statement at the top:
```csharp
using System.Text.Encodings.Web;
```

Replace the vulnerable code at line 11:
```csharp
string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

With:
```csharp
string encodedMessage = HtmlEncoder.Default.Encode(banner.Message);
string html = $"<div class='welcome-banner'>Welcome back, {encodedMessage}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

## Explanation

The vulnerability exists because `banner.Message` (containing untrusted user input from the query string) is interpolated directly into an HTML string without encoding. When the HTML is written to the response via `HttpResponse.WriteAsync()`, the browser interprets the injected HTML/JavaScript as code rather than data.

The fix applies HTML encoding via `HtmlEncoder.Default.Encode()` before the value is embedded in the HTML string. This converts dangerous characters (`<`, `>`, `&`, `"`, etc.) into HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`) so they are treated as data, not markup. The encoding is context-appropriate for HTML body text and does not interfere with legitimate content containing special characters.

The fix touches only the vulnerable data flow point and preserves the existing code structure and response format.

## Behaviour changes

Input with HTML/script content (e.g., `?nickname=<script>alert('xss')</script>`) is now harmlessly rendered as visible text instead of executing. Special characters in legitimate input (e.g., `?nickname=Alice&Bob`) render correctly with entities decoded by the browser (displayed as "Alice&Bob").
