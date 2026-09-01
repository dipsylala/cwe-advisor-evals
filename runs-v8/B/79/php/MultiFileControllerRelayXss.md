## Verdict

Real vulnerability confirmed. User-controlled input from `$_POST['comment']` flows unencoded to an HTML echo statement on line 11 of ConfirmationPageRenderer.php.

## Source

`$_POST['comment']` in TicketController.php (line 12), propagated through TicketService and NotificationDispatcher, reaches ConfirmationPageRenderer as the `$message` parameter containing untrusted data.

## Fix

**ConfirmationPageRenderer.php, line 11:**

```php
// Before:
echo '<p>' . $message . '</p>';

// After:
echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

The `htmlspecialchars()` call with explicit flags encodes HTML special characters (`<`, `>`, `&`, `"`, `'`) appropriate to the HTML body context. The flags ensure:
- `ENT_QUOTES`: Both double and single quotes are encoded
- `ENT_SUBSTITUTE`: Invalid UTF-8 sequences become replacement characters rather than disappearing
- `ENT_HTML5`: Use HTML5 entity definitions for correct encoding

## Explanation

The `$message` variable containing user-controlled comment text is echoed directly into an HTML paragraph element without encoding. An attacker can inject script payloads via `<script>alert('xss')</script>`, event handlers like `<img onerror=alert('xss')>`, or other executable HTML/JavaScript. 

Applying `htmlspecialchars()` with the specified flags at the output sink neutralizes these by converting dangerous characters into HTML entities (`<` becomes `&lt;`, `>` becomes `&gt;`, etc.), ensuring the injected payload renders as literal text rather than executable code.

## Behaviour changes

Legitimate text containing HTML special characters (angle brackets, ampersands, quotes) that previously rendered as literal text will continue to do so. Text that previously allowed injection (e.g., `<script>alert(1)</script>`) will now render as escaped entities visible to the user rather than executing. No functional change for legitimate input; injected payloads are now neutralized.
