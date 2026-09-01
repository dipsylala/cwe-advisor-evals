## Verdict

This is a confirmed CWE-79 (Cross-site Scripting) vulnerability. User-supplied input from `$_POST['author']` and `$_POST['body']` flows directly into HTML output without HTML escaping, allowing arbitrary JavaScript injection.

## Source

The vulnerability originates at lines 7–8 where unsanitized POST parameters are retrieved:
```php
'author' => $_POST['author'] ?? '',
'body' => $_POST['body'] ?? ''
```

The tainted data is then concatenated into HTML at lines 16–17:
```php
$html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
$html .= '<p class="review-body">' . $review['body'] . '</p>';
```

The data reaches the sink at line 26 via `echo $card`.

## Fix

Escape the user-supplied values using `htmlspecialchars()` with `ENT_QUOTES` flag to neutralize both HTML and attribute injection:

```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}
```

The `ENT_QUOTES` flag ensures both double and single quotes are escaped, preventing attribute-based injection. The `'UTF-8'` charset parameter ensures correct handling of non-ASCII characters.

## Explanation

User-supplied input must be HTML-escaped when inserted into an HTML context to prevent XSS. The `htmlspecialchars()` function converts special characters (`<`, `>`, `&`, `"`, `'`) to their HTML entity equivalents, ensuring they render as literal text rather than markup.

The fix prevents an attacker from closing the tag and injecting arbitrary HTML or JavaScript. For example, an attacker-supplied `author` of `"><script>alert('XSS')</script><"` will be rendered as the literal string with all special characters escaped, not as executable code.
