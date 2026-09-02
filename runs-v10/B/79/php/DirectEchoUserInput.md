## Verdict

Exploitable

## Source

`$_POST['note']` (line 27) - untrusted user input from POST data

## Fix

**Vulnerable code:**
```php
echo "<div class='requester-note'>Note from requester: " . $_POST['note'] . "</div>";
```

**Fixed code:**
```php
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($_POST['note'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . "</div>";
```

## Explanation

The original code echoes untrusted POST data directly into an HTML context without any encoding. An attacker can inject malicious JavaScript through `$_POST['note']` - for example, `<script>alert('XSS')</script>` or `" onload="alert('XSS')` - which will execute in the victim's browser. The fix applies `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit UTF-8 encoding to convert special characters into HTML entities. This ensures the input remains text data and cannot break out of the HTML context to execute as code. The flags ensure single quotes are escaped (ENT_QUOTES), invalid UTF-8 sequences are replaced rather than dropped (ENT_SUBSTITUTE), and HTML5 named entities are recognized (ENT_HTML5).

## Behaviour changes

None - `htmlspecialchars()` transforms the string content while preserving the intended text to be displayed. Legitimate content containing `<`, `>`, `&`, and quotes will now display with entities visible to the user only if viewed as source; the browser renders them correctly as their intended characters.
