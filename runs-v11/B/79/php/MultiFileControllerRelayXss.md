## Verdict

Exploitable. User-controlled input flows unencoded from `$_POST['comment']` through the call chain to an unescaped echo statement in HTML body context, allowing XSS injection.

## Source

`$_POST['comment']` in TicketController.php line 12 - untrusted user-supplied form data passed through TicketService::createTicket() → NotificationDispatcher::sendConfirmation() → ConfirmationPageRenderer::render().

## Fix

**Vulnerable code (ConfirmationPageRenderer.php, line 11):**
```php
echo '<p>' . $message . '</p>';
```

**Fixed code:**
```php
echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

## Explanation

The message variable receives untrusted user input (via the $comment parameter from $_POST) and is echoed directly into the HTML without encoding. This allows an attacker to inject arbitrary HTML and JavaScript by submitting a comment like `<img src=x onerror=alert('XSS')>`. The fix applies `htmlspecialchars()` with explicit flags (`ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and UTF-8 encoding) to encode the output appropriately for HTML body context, converting dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entities so they render as text rather than executable markup.

## Behaviour changes

None. The htmlspecialchars() call preserves the sink contract: it encodes the value in-place for HTML context and returns the encoded string, which is then concatenated and echoed exactly as before. The user sees the same visual output (with any raw markup displayed as text), and all legitimate content containing `<`, `&`, and quotes still renders correctly as escaped text.
