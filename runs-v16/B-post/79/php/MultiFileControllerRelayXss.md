## Verdict

**CONFIRMED EXPLOITABLE**

Untrusted data from `$_POST['comment']` flows through the service layer and is rendered in HTML context without encoding.

## Source

`$_POST['comment']` in TicketController.php (line 12), passed via TicketService and NotificationDispatcher to ConfirmationPageRenderer.

## Fix

In ConfirmationPageRenderer.php line 11, replace:

```php
echo '<p>' . $message . '</p>';
```

With:

```php
echo '<p>' . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

## Explanation

The `$message` parameter receives a concatenation of user input (`$_POST['comment']`) via the service layer. When echoed directly into HTML, an attacker can inject arbitrary HTML/JavaScript. The fix applies `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` to encode the entire message: `<`, `>`, `&`, and both single and double quotes are converted to HTML entities, preventing script injection. `ENT_SUBSTITUTE` also handles any invalid UTF-8 sequences by replacing them with the Unicode replacement character instead of dropping them silently.

The fix preserves the surrounding HTML structure (`<p>` and `</p>` tags remain unencoded) while neutralizing the user-supplied content.

## Behaviour changes

- Legitimate content containing `<`, `>`, `&`, or quotes now renders with entity encoding visible to the browser: `<`, `>`, `&`, `"`, `'` appear as their HTML entity representations in the output.
- Invalid UTF-8 byte sequences (if any occur upstream) are replaced with Unicode replacement character `U+FFFD` instead of being silently dropped.
- No change to the page structure or layout; only the character representation changes in the rendered markup and browser display.
