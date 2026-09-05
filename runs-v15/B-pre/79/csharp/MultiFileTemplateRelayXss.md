## Verdict

Exploitable. The untrusted `nickname` query parameter flows from `ProfileController.Welcome()` through `GreetingService.BuildAndRenderBanner()` to `WelcomeBannerRenderer.Write()`, where it is interpolated into HTML and written to the response without encoding. Input validation (trim, substring) does not prevent XSS; an attacker can inject HTML/JavaScript tags that the browser will execute.

## Source

Query parameter `nickname` in `ProfileController.Welcome()` (line 21 of ProfileController.cs):
```
string nickname = Request.Query["nickname"].ToString();
```

This untrusted value is passed through `GreetingService.BuildAndRenderBanner()` as `request.Nickname`, then to `WelcomeBannerRenderer.Write()` as `banner.Message`.

## Fix

**Vulnerable code** (WelcomeBannerRenderer.cs, line 11):
```csharp
string html = $"<div class='welcome-banner'>Welcome back, {banner.Message}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

**Fixed code**:
```csharp
string html = $"<div class='welcome-banner'>Welcome back, {System.Net.WebUtility.HtmlEncode(banner.Message)}! Last visit logged at {banner.RequestedAt:u}.</div>";
```

## Explanation

The fix applies HTML encoding to `banner.Message` at the output sink using `System.Net.WebUtility.HtmlEncode()`. This encodes dangerous characters (`<`, `>`, `&`, `"`) as HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`), preventing the browser from interpreting them as markup or script. The payload `<img src=x onerror=alert(1)>` becomes `&lt;img src=x onerror=alert(1)&gt;`, rendered as harmless text. Context-specific encoding at the sink is the primary defence against XSS; the input validation (trim, length limit) in `GreetingService` does not encode and therefore does not prevent this attack.

## Behaviour changes

None. `System.Net.WebUtility.HtmlEncode()` encodes the value in-place within the string interpolation. The `WriteAsync()` call receives the same HTML structure with safely encoded content, maintaining the original contract of writing the response to the client.
