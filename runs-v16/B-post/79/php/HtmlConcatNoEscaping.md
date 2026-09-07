## Verdict

exploitable

## Source

`$_POST['author']` and `$_POST['body']` on lines 7-8 of HtmlConcatNoEscaping.php. User-submitted form data flows directly into HTML output without escaping.

## Fix

**Vulnerable code (lines 15-18):**
```php
$html = '<div class="review-card">';
$html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
$html .= '<p class="review-body">' . $review['body'] . '</p>';
$html .= '</div>';
```

**Fixed code:**
```php
$html = '<div class="review-card">';
$html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</h3>';
$html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
$html .= '</div>';
```

## Explanation

The vulnerability exists because `$review['author']` and `$review['body']` are inserted directly into HTML output without escaping. An attacker submitting `<img src=x onerror="alert('XSS')">` as the author or body breaks out of the text context and executes arbitrary JavaScript in the victim's browser.

The fix applies `htmlspecialchars()` with the recommended PHP flags (`ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5`, explicit `'UTF-8'` charset) to encode dangerous HTML metacharacters (`<`, `>`, `&`, `"`, `'`) at each point of concatenation. This ensures untrusted data remains data, not executable markup, while preserving legitimate content containing these characters through safe entity encoding.

## Behaviour changes

None. The `htmlspecialchars()` function does not alter the structure or flow of the code. It transforms the output by escaping metacharacters but does not change return values, discard output, or alter control flow. The echo on line 26 still outputs the same HTML structure; the difference is that special characters in user input are now encoded (e.g., `<` becomes `&lt;`), preventing injection.
