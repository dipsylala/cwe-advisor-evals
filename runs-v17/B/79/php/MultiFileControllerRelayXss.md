## Verdict

**EXPLOITABLE** - The vulnerability is real and exploitable. Untrusted user input from `$_POST['comment']` flows without encoding to an HTML output context in `ConfirmationPageRenderer::render()` at line 11.

## Source

The data flow begins at `TicketController::handleSubmit()` line 12, where `$_POST['comment']` is read directly from user input. This untrusted value is passed through the call chain:

1. `TicketController::handleSubmit()` (line 12) reads `$_POST['comment']`
2. `TicketService::createTicket()` (line 21) receives it as the `$comment` parameter
3. `NotificationDispatcher::sendConfirmation()` (line 17) receives it as the `$comment` parameter
4. Line 12 concatenates it into the `$message` string: `$greeting . " We've logged ticket {$ticketId}. Your note: " . $comment`
5. `ConfirmationPageRenderer::render()` (line 15) receives this `$message` as a parameter
6. Line 11 echoes it directly without encoding into the HTML body context

An attacker can inject malicious HTML or JavaScript through the `comment` POST parameter, which will be rendered in victims' browsers without escaping. Example payload: `<img src=x onerror="alert('XSS')">` would execute JavaScript in the browser.

## Fix

### File: ConfirmationPageRenderer.php

```php
<?php

// Renders the HTML confirmation page shown after a ticket is filed.
class ConfirmationPageRenderer
{
    public function render(string $ticketId, string $message): void
    {
        echo '<!DOCTYPE html><html><head><title>Ticket Submitted</title></head><body>';
        echo '<div class="confirmation" data-ticket-id="' . htmlspecialchars($ticketId, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '">';
        echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
        echo '</div></body></html>';
    }
}
```

## Explanation

The fix applies context-aware output encoding at the HTML rendering sink. The `htmlspecialchars()` function with flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit `'UTF-8'` charset is applied to both `$ticketId` (line 9) and `$message` (line 11).

The encoding converts dangerous characters that could break out of the HTML context:
- `<` becomes `&lt;`
- `>` becomes `&gt;`
- `&` becomes `&amp;`
- `"` becomes `&quot;` (ENT_QUOTES)
- `'` becomes `&#039;` (ENT_QUOTES)

Invalid UTF-8 sequences are replaced with U+FFFD (ENT_SUBSTITUTE), preventing silent data loss. This ensures that untrusted user input is rendered as data rather than executable code, while preserving the display of legitimate content containing these characters.

The fix follows the PHP-specific guidance from the knowledge base: use `htmlspecialchars()` with explicit flags for HTML output contexts, and apply encoding at each output sink. The `$ticketId` is also encoded defensively, even though it originates from `uniqid()` - applying encoding at all sinks is the safest pattern when data flows through multiple layers.

## Behaviour changes

- **XSS prevention**: The output now safely encodes all untrusted data, preventing JavaScript injection through the comment parameter
- **Visual preservation**: Legitimate characters like `<`, `>`, `&`, and quotes in user input now display properly escaped in the browser, maintaining readability while blocking code execution
- **No functional regression**: The HTML structure and page rendering remain identical; only the content is now safely escaped, so existing non-malicious messages display correctly
