## Verdict

Exploitable. The finding is a real vulnerability. Untrusted user input from `$_POST['comment']` flows through the TicketController → TicketService → NotificationDispatcher → ConfirmationPageRenderer call chain and is rendered directly into HTML without encoding at line 11.

## Source

- **Entry point**: `$_POST['comment']` in TicketController::handleSubmit()
- **Flow**: TicketController.php line 12 → TicketService.php line 17 → NotificationDispatcher.php line 12 → ConfirmationPageRenderer.php line 11
- **Sink**: `echo '<p>' . $message . '</p>';` in ConfirmationPageRenderer.php line 11

The message is concatenated into a string in NotificationDispatcher and passed to ConfirmationPageRenderer without any encoding. At the sink (line 11 of ConfirmationPageRenderer), the raw untrusted string is echoed directly into HTML content, allowing XSS injection.

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
        // FIXED: Output encoding applied to message
        echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
        echo '</div></body></html>';
    }
}
```

## Explanation

The vulnerability occurs because untrusted user input flows directly to the output sink without encoding. The fix applies `htmlspecialchars()` with flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit UTF-8 encoding to both the `$message` parameter (line 11) and the `$ticketId` data attribute (line 9). This ensures that HTML metacharacters (`<`, `>`, `"`, `'`, `&`) are converted to their entity equivalents, preventing the browser from interpreting attacker-supplied input as executable code. The `ENT_QUOTES` flag handles both double and single quotes, `ENT_SUBSTITUTE` converts invalid UTF-8 to a replacement character, and `ENT_HTML5` uses HTML5 entities.

## Behaviour changes

- Characters with special meaning in HTML (`<`, `>`, `&`, `"`, `'`) are now encoded as entity references when output
- Legitimate user content that includes these characters will display correctly as encoded entities (standard HTML behavior for text content)
- The data-ticket-id attribute encoding prevents attackers from breaking out of the attribute to inject handlers
- No changes to function signatures, return values, or application logic; only output encoding is applied
