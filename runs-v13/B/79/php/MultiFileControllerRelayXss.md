## Verdict

**VULNERABLE** — Line 11 of `ConfirmationPageRenderer.php` echoes the `$message` parameter directly into HTML body context without encoding. The `$message` contains untrusted user data from `$_POST['comment']` that flows through the call chain: `TicketController::handleSubmit()` → `TicketService::createTicket()` → `NotificationDispatcher::sendConfirmation()` → `ConfirmationPageRenderer::render()`. An attacker can inject arbitrary HTML and JavaScript that executes in the victim's browser.

## Source

The vulnerability originates at line 12 of `TicketController.php`:

```php
$comment = $_POST['comment'] ?? '';
```

This untrusted data is passed to `TicketService::createTicket()`, concatenated into a confirmation message at line 12 of `NotificationDispatcher.php`:

```php
$message = $greeting . " We've logged ticket {$ticketId}. Your note: " . $comment;
```

Finally, it reaches the unencoded output sink at line 11 of `ConfirmationPageRenderer.php`:

```php
echo '<p>' . $message . '</p>';
```

## Fix

Replace line 11 of `ConfirmationPageRenderer.php` with:

```php
echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

Optionally, also encode the `data-ticket-id` attribute on line 9 for defense-in-depth (the `$ticketId` is generated with `uniqid()` and is safe from injection, but encoding attributes as a habit prevents future mistakes):

```php
echo '<div class="confirmation" data-ticket-id="' . htmlspecialchars($ticketId, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '">';
```

## Explanation

`htmlspecialchars()` with the specified flags converts HTML-sensitive characters to entities:
- `<` becomes `&lt;`, `>` becomes `&gt;` — prevents tag injection
- `&` becomes `&amp;` — prevents entity-based bypasses
- `"` becomes `&quot;`, `'` becomes `&#039;` (with `ENT_QUOTES`) — prevents attribute breakout
- `ENT_SUBSTITUTE` replaces invalid UTF-8 sequences with the Unicode replacement character, preventing silent data loss
- `ENT_HTML5` uses HTML5 entity definitions (the appropriate standard for modern web pages)
- Explicit `'UTF-8'` ensures the encoding is never misinterpreted

This is the primary defence for XSS in HTML body content. The attacker's payload, e.g. `<script>alert('xss')</script>`, becomes `&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;` and renders as plain text in the page rather than executing code.

## Behaviour changes

- Legitimate content containing `<`, `>`, `&`, and quotes now renders correctly (e.g. if a customer submits "I need a < comparison operator explained", it displays as written instead of breaking the page structure).
- Any XSS payload injected via `$_POST['comment']` is neutralized and displayed as literal text to the end user.
- The HTML structure of the confirmation page remains unchanged — only the user-supplied content is escaped.
- Response size increases slightly due to entity encoding of special characters, which is negligible for typical message lengths.
