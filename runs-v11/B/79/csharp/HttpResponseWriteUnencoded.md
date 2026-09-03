## Verdict

Confirmed exploitable. Untrusted query string data flows directly into HTML output without encoding.

## Source

`Request.QueryString["ticketRef"]` (line 11) - untrusted user input from URL query parameter.

## Fix

**Vulnerable code (line 18):**
```csharp
Response.Write("<p>Showing status for ticket: " + ticketRef + "</p>");
```

**Fixed code:**
```csharp
Response.Write("<p>Showing status for ticket: " + System.Net.WebUtility.HtmlEncode(ticketRef) + "</p>");
```

Alternatively, import `System.Net` at the top and simplify:
```csharp
Response.Write("<p>Showing status for ticket: " + WebUtility.HtmlEncode(ticketRef) + "</p>");
```

## Explanation

The vulnerability occurs because `ticketRef` is obtained from an untrusted query string parameter and concatenated directly into HTML output via `Response.Write()` without any encoding. This allows an attacker to inject malicious markup or scripts by passing payloads like `?ticketRef=<img src=x onerror="alert('XSS')">`.

The fix applies HTML encoding via `System.Net.WebUtility.HtmlEncode()`, which converts dangerous characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`). This ensures that user input is treated as data rather than executable HTML, preventing script injection while allowing legitimate ticket reference values to display correctly.

## Behaviour changes

- Angle brackets, ampersands, and quotes in `ticketRef` will be displayed as HTML entities rather than as literal characters. For example, if a ticket reference contains `A&B`, it will render as `A&amp;B` to the user.
- No functional change to legitimate use: valid ticket references (alphanumeric, dashes, etc.) will display identically.
- Malicious payloads attempting HTML/JavaScript injection will be neutralized and displayed as escaped text rather than executed.
