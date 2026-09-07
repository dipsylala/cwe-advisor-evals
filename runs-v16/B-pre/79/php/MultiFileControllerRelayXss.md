## Verdict

Exploitable.

## Source

`$_POST['comment']` in TicketController, line 12. User input is read directly from the POST request without validation or sanitization.

## Fix

**Vulnerable code** (ConfirmationPageRenderer.php, line 11):
```php
echo '<p>' . $message . '</p>';
```

**Fixed code**:
```php
echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

## Explanation

The `$message` parameter contains untrusted user input that flows through the application unescaped: it originates from `$_POST['comment']` in TicketController, passes through TicketService and NotificationDispatcher where it is concatenated into a larger string, and reaches ConfirmationPageRenderer where it is output directly to HTML via `echo` without encoding.

The fix applies context-aware HTML encoding using `htmlspecialchars()` with the flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit UTF-8 charset. This ensures special characters (`<`, `>`, `&`, `"`, `'`) are converted to HTML entities, preventing script injection. The message remains legible after encoding—legitimate content containing these characters (e.g., "5 < 10" or "O'Reilly") renders correctly with the special characters visible, while malicious payloads like `<script>alert('xss')</script>` are rendered as literal text and never executed.

## Behaviour changes

None. The fix preserves the original output—the HTML structure and the visual presentation remain identical. `htmlspecialchars()` returns a string in the same position as the original, and `echo` sends it to output exactly as before. Legitimate content that happens to contain `<`, `>`, `&`, or quotes will now be displayed with entities visible, but that is the correct behaviour for user input in HTML body content—those characters belong escaped in this context.
