## Verdict

**exploitable**

## Source

Lines 7–8, `$_POST['author']` and `$_POST['body']`: untrusted user input from form submission, retrieved without validation or encoding.

## Fix

**Vulnerable code (lines 15–18):**
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

The vulnerability exists because user-supplied data from `$_POST` is concatenated directly into HTML markup without any output encoding. When the HTML string is echoed to the browser (line 26), an attacker can inject arbitrary HTML or JavaScript by submitting payloads in the author or body fields (for example, `<img src=x onerror="alert('XSS')">` or `<script>alert('XSS')</script>`), which would execute in victims' browsers.

The fix applies `htmlspecialchars()` with the flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit UTF-8 encoding to both data fields before rendering them into HTML. This escapes special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, ensuring they are treated as data rather than code. `ENT_SUBSTITUTE` prevents silent data loss on malformed UTF-8.

## Behaviour changes

None. The escaping preserves the semantic rendering of legitimate content. Users can submit text containing `<`, `>`, `&`, or quotes; these characters will be displayed as escaped HTML entities in the browser, which is the correct and expected behavior for HTML output that is not intended to contain markup.
