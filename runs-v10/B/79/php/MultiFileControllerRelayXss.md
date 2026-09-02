## Verdict

Exploitable. User-supplied input flows from `$_POST['comment']` through four files and is rendered directly into HTML at line 11 without any encoding, allowing arbitrary script injection.

## Source

`$_POST['comment']` in TicketController.php (line 12), passed through TicketService::createTicket() → NotificationDispatcher::sendConfirmation() → ConfirmationPageRenderer::render() to the sink.

The `$comment` value is concatenated into `$message` in NotificationDispatcher.php (line 12), then echoed unencoded in ConfirmationPageRenderer.php (line 11).

## Fix

**Vulnerable Code (ConfirmationPageRenderer.php, lines 6–13):**

```php
public function render(string $ticketId, string $message): void
{
    echo '<!DOCTYPE html><html><head><title>Ticket Submitted</title></head><body>';
    echo '<div class="confirmation" data-ticket-id="' . $ticketId . '">';
    // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    echo '<p>' . $message . '</p>';  // VULNERABLE: $message contains unencoded user input
    echo '</div></body></html>';
}
```

**Fixed Code:**

```php
public function render(string $ticketId, string $message): void
{
    echo '<!DOCTYPE html><html><head><title>Ticket Submitted</title></head><body>';
    echo '<div class="confirmation" data-ticket-id="' . htmlspecialchars($ticketId, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '">';
    echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
    echo '</div></body></html>';
}
```

## Explanation

The vulnerability occurs because `$message` is built from the user-supplied `$_POST['comment']` parameter and echoed directly into HTML markup without any encoding. An attacker can inject arbitrary HTML and JavaScript, such as `<img src=x onerror="alert('xss')">` or `<script>alert('xss')</script>`, which executes in the victim's browser.

The fix applies `htmlspecialchars()` with flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit `'UTF-8'` encoding at the output sink. This converts dangerous characters to HTML entities: `<` becomes `&lt;`, `>` becomes `&gt;`, `"` becomes `&quot;`, and `'` becomes `&#039;`, preventing any user input from being interpreted as HTML or JavaScript. The `ENT_SUBSTITUTE` flag ensures invalid UTF-8 sequences are replaced rather than silently dropped.

Also applied encoding to `$ticketId` in the HTML attribute on line 9 (before the fix was applied), which, while internally generated and not directly user-controlled, follows defence-in-depth principles and prevents breakout if ID generation changes.

## Behaviour changes

None. The `htmlspecialchars()` function returns the encoded string, which is then echoed—the same output behavior as before. The render method returns void and produces HTML output to stdout, which is unchanged in contract. The encoding only affects the internal representation: the browser receives entity-encoded characters rather than raw special characters, but displays them identically to users. Legitimate content containing `<`, `>`, `&`, quotes, and other special characters renders correctly as text rather than as markup.
