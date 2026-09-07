## Verdict

CWE-79 vulnerability confirmed. User-controlled input from `$_POST['author']` and `$_POST['body']` is concatenated directly into HTML output without escaping, allowing script injection.

## Source

Lines 16-17 in `renderReviewCard()`:

```php
$html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
$html .= '<p class="review-body">' . $review['body'] . '</p>';
```

The `$review['author']` and `$review['body']` values come directly from `$_POST` without sanitization, and are embedded into HTML context without escaping.

## Fix

Escape the user-controlled values using `htmlspecialchars()` to neutralize HTML metacharacters:

```php
$html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES, 'UTF-8') . '</h3>';
$html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES, 'UTF-8') . '</p>';
```

## Explanation

The vulnerability occurs because user input from the POST request is directly concatenated into HTML markup without escaping. An attacker can submit a review with content like `<script>alert('XSS')</script>` which will be executed in the browser.

`htmlspecialchars()` converts HTML special characters (`<`, `>`, `&`, `"`, `'`) to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), neutralizing them as markup. The flags `ENT_QUOTES` and `'UTF-8'` ensure both double and single quotes are escaped, and the charset is explicitly specified to prevent encoding bypasses.
