## Verdict

Exploitable

## Source

`$_POST['note']` at line 27 — attacker-controlled user input from HTTP POST request

## Fix

**Vulnerable code (line 27):**
```php
echo "<div class='requester-note'>Note from requester: " . $_POST['note'] . "</div>";
```

**Fixed code:**
```php
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($_POST['note'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . "</div>";
```

## Explanation

The vulnerability occurs because `$_POST['note']` flows directly to an HTML body output context without encoding. An attacker can inject HTML and JavaScript by submitting a payload like `"><script>alert('XSS')</script><div class="`. The fix applies `htmlspecialchars()` with comprehensive flags (`ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5`) to encode all special characters that could enable breakout or script execution. The `ENT_SUBSTITUTE` flag ensures invalid UTF-8 sequences are replaced rather than silently dropped. The fix is applied at the sink (the `echo` statement) where the data crosses into HTML, which is the appropriate output-encoding location for this context.

## Behaviour changes

None. The fix preserves the existing output contract: the user's note still appears in the `<div>`, but special characters (`<`, `>`, `&`, `"`, `'`) are HTML-entity-encoded, preventing injection while displaying the legitimate content correctly.
