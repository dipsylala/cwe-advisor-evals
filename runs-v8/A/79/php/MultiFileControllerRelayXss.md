## Verdict

Real XSS vulnerability. The `$message` parameter, containing user-controlled input from `$_POST['comment']` through the call chain, is echoed directly into HTML without escaping on line 11.

## Source

TicketController reads `$_POST['comment']` and passes it to TicketService::createTicket(). TicketService passes it to NotificationDispatcher::sendConfirmation(), which concatenates it into `$message` on line 12. NotificationDispatcher then passes `$message` to ConfirmationPageRenderer::render(), which echoes it unsanitized into the HTML output on line 11.

## Fix

```php
echo '<p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>';
```

Replace line 11 in ConfirmationPageRenderer.php to use `htmlspecialchars()` with `ENT_QUOTES` and `UTF-8` encoding, which escapes both single and double quotes along with other HTML metacharacters.

## Explanation

An attacker can inject arbitrary HTML or JavaScript by passing malicious content in the `comment` parameter. For example, submitting `<script>alert('XSS')</script>` in the comment field causes that script to execute in the victim's browser when the confirmation page is rendered.

The fix escapes all HTML metacharacters, converting dangerous characters like `<`, `>`, `"`, and `'` into their HTML entities (`&lt;`, `&gt;`, `&quot;`, `&#039;`). This prevents the browser from interpreting user input as markup or script, transforming it into safe display text instead.

`ENT_QUOTES` is required here because the message is placed inside an attribute-free text context, but it's the safest default. `UTF-8` is the charset parameter and should match the application's character encoding.
