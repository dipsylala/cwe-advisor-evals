## Verdict

Confirmed. Lines 10-11 capture untrusted user input via `$cgi->param()`, and line 18 interpolates these variables directly into HTML output without any encoding, enabling reflected XSS injection.

## Source

User-controlled input enters at lines 10-11:
- `my $guest_name = $cgi->param('guest_name');`
- `my $event_title = $cgi->param('event_title');`

Both parameters come directly from HTTP request data with no validation or sanitization.

## Fix

**1. Add import for HTML::Entities:**
```
use HTML::Entities;
```

**2. Replace line 18 with:**
```perl
print "<h2>Thanks, " . encode_entities($guest_name) . "! You're confirmed for " . encode_entities($event_title) . ".</h2>\n";
```

Alternatively, using Perl interpolation syntax:
```perl
my $safe_name = encode_entities($guest_name);
my $safe_title = encode_entities($event_title);
print "<h2>Thanks, $safe_name! You're confirmed for $safe_title.</h2>\n";
```

## Explanation

The vulnerability results from direct variable interpolation of untrusted data into an HTML context. The fix applies `encode_entities()` from HTML::Entities to escape special HTML characters (`<`, `>`, `&`, `"`, `'`) before output. This prevents the browser from interpreting user input as HTML tags or script content. The encoded values are safe to include in HTML body and attribute contexts. `encode_entities()` with no second argument uses a broad default escaping set suitable for HTML output.

## Behaviour changes

- **Input handling**: Untrusted parameters are still accepted without format validation (as before).
- **Output rendering**: Any reserved HTML characters in user input (`<`, `>`, `&`, `"`, `'`) are now output as entity references (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#39;`) and display as literal characters in the browser instead of being interpreted as markup.
- **Legitimate content**: Text containing special characters (e.g., `Smith & Sons`, `Price: 25 < 50`) will display correctly because entities are decoded by the browser.
- **Attack surface**: Script payloads like `<script>alert(1)</script>` or event handlers like `" onmouseover="alert(1)` are now rendered as harmless text.
- **No change to request/response flow**: HTTP headers, CGI execution, and the overall application flow are unaffected.
