## Verdict
CONFIRMED - CWE-79 Cross-site Scripting vulnerability via unsanitized user input in HTML context.

## Source
The vulnerability originates in `TicketController::handleSubmit()` which reads untrusted user input from `$_POST['comment']`. This value flows through `TicketService::createTicket()` and `NotificationDispatcher::sendConfirmation()` where it is concatenated into the `$message` variable. The message is then passed to `ConfirmationPageRenderer::render()` and output directly to HTML without escaping.

## Fix
The vulnerable code echoes user-controlled data directly into HTML without escaping. The fix applies `htmlspecialchars()` to neutralize HTML metacharacters before output, preventing script injection.

### File: ConfirmationPageRenderer.php
```php
<?php

// Renders the HTML confirmation page shown after a ticket is filed.
class ConfirmationPageRenderer
{
    public function render(string $ticketId, string $message): void
    {
        echo '<!DOCTYPE html><html><head><title>Ticket Submitted</title></head><body>';
        echo '<div class="confirmation" data-ticket-id="' . htmlspecialchars($ticketId, ENT_QUOTES, 'UTF-8') . '">';
        echo '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>';
        echo '</div></body></html>';
    }
}
```

## Explanation
The fix applies `htmlspecialchars()` to both output locations in the render method:

1. **Line 9 (data attribute)**: Escapes `$ticketId` to prevent attribute-based XSS, even though this value is generated safely by `uniqid()`. This provides defense-in-depth.

2. **Line 11 (text content)**: Escapes `$message` to neutralize HTML and JavaScript metacharacters. The concatenated message contains untrusted user input from `$_POST['comment']`, making this the critical sink. Characters like `<`, `>`, `"`, `'`, and `&` are converted to HTML entities (`&lt;`, `&gt;`, `&quot;`, `&#039;`, `&amp;`), which prevents the browser from interpreting them as markup or script delimiters.

The `ENT_QUOTES` flag ensures both double and single quotes are escaped, and `'UTF-8'` specifies the character encoding. This allows safe rendering of legitimate user content while blocking injected scripts.
