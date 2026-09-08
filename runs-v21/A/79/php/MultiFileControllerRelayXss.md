## Verdict

The vulnerability is confirmed. Untrusted user input flows from `$_POST['comment']` through multiple layers without sanitization and is rendered directly into HTML output without escaping.

## Source

The data flow is:
1. **TicketController.php** line 12: `$comment = $_POST['comment'] ?? '';` - reads untrusted user input
2. **TicketService.php** line 17: `$dispatcher->sendConfirmation($ticketId, $customerName, $comment);` - passes comment downstream
3. **NotificationDispatcher.php** line 12: `$message = $greeting . " We've logged ticket {$ticketId}. Your note: " . $comment;` - includes comment in message string
4. **ConfirmationPageRenderer.php** line 11: `echo '<p>' . $message . '</p>';` - outputs to HTML without escaping

The sink is line 11 of ConfirmationPageRenderer.php, where the unsanitized message containing user input is echoed directly into the HTML response.

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
        echo '<div class="confirmation" data-ticket-id="' . htmlspecialchars($ticketId, ENT_QUOTES, 'UTF-8') . '">';
        // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
        echo '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>';
        echo '</div></body></html>';
    }
}
```

## Explanation

The vulnerability occurs because user-controlled data (`$comment`) is passed through the call chain without sanitization and rendered directly into HTML at the sink. An attacker can inject malicious HTML or JavaScript, such as `<script>alert('XSS')</script>`, which will execute in the victim's browser.

The fix applies `htmlspecialchars()` with `ENT_QUOTES` and `UTF-8` encoding to both the `$ticketId` and `$message` variables before outputting them. This escapes HTML special characters (`<`, `>`, `&`, `"`, and `'`) to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), preventing the browser from interpreting user input as code.

The `ENT_QUOTES` flag ensures both double and single quotes are escaped, and specifying `UTF-8` ensures proper encoding handling for international characters.
