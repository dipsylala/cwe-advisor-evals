## Verdict

exploitable

## Source

Line 13: `$_POST['note']` receives untrusted user input from a POST request, with no prior validation or sanitization.

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

The original code renders user-supplied input directly into HTML body text without encoding, allowing an attacker to inject arbitrary scripts. For example, a note containing `<img src=x onerror="alert('XSS')">` would execute JavaScript in the victim's browser. The fix applies context-aware output encoding using `htmlspecialchars()` with the `ENT_QUOTES`, `ENT_SUBSTITUTE`, and `ENT_HTML5` flags and explicit UTF-8 encoding. This converts dangerous characters (`<`, `>`, `"`, `'`, `&`) to HTML entities, ensuring user input remains data and cannot be interpreted as executable code.

## Behaviour changes

The encoded output will display HTML special characters as entities (e.g., `<` becomes `&lt;`, `&` becomes `&amp;`, `"` becomes `&quot;`). For example, if a user submits a note containing `"Hello & goodbye"`, it will render as `&quot;Hello &amp; goodbye&quot;`. This is the correct behaviour—user input is never executed as markup, and legitimate content containing these characters is displayed safely and accurately.
