## Verdict

**Confirmed.** The application outputs user-supplied input without HTML escaping, enabling script injection.

## Source

User input enters at `TicketController::handleSubmit()` via `$_POST['customer_name']` and `$_POST['comment']`. The controller passes these values to `TicketService::createTicket()`, which forwards them to `NotificationDispatcher::sendConfirmation()`. The dispatcher concatenates the inputs into a message string and passes it to `ConfirmationPageRenderer::render()`, where the message is output directly into HTML without escaping.

## Fix

In `ConfirmationPageRenderer.php` at line 11, replace:

```php
echo '<p>' . $message . '</p>';
```

with:

```php
echo '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>';
```

This escapes special characters in the message for safe HTML output. The `ENT_QUOTES` flag ensures both double and single quotes are escaped, and `'UTF-8'` specifies the encoding.

Additionally, escaping should also be applied to `$ticketId` at line 9 for consistency and defense-in-depth, since it too is included in an HTML attribute:

```php
echo '<div class="confirmation" data-ticket-id="' . htmlspecialchars($ticketId, ENT_QUOTES, 'UTF-8') . '">';
```

## Explanation

The vulnerability arises because untrusted input from POST parameters flows through the call chain without validation or sanitization, reaching a sink that renders it as HTML content without escaping. An attacker can inject malicious HTML or JavaScript (e.g., `<script>alert('XSS')</script>` or event handlers like `<img src=x onerror="alert('XSS')">`) via the `customer_name` or `comment` fields.

The fix applies HTML entity encoding at the output point, converting special characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`). This ensures the browser treats the input as literal text rather than HTML markup or JavaScript code. The `ENT_QUOTES` flag is critical for this context because the attribute and element content both need protection; using `ENT_HTML5` or `ENT_QUOTES` ensures all context-sensitive escaping rules are applied.
