## Verdict
Confirmed CWE-79: user-controlled input from `$_POST['author']` and `$_POST['body']` is concatenated directly into HTML output without escaping, allowing arbitrary JavaScript injection.

## Source
Lines 16-17 concatenate unescaped POST data into the HTML string:
```php
$html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
$html .= '<p class="review-body">' . $review['body'] . '</p>';
```

The data originates from `$_POST` superglobal (lines 7-8) and flows through to the `echo` statement on line 26 without any HTML escaping.

## Fix
Escape both user inputs using `htmlspecialchars()` with the `ENT_QUOTES` flag to handle both double and single quotes:

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

Apply `htmlspecialchars()` at the point where user data is inserted into the HTML string to convert special characters (`<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents.

## Explanation
The vulnerability occurs because user-submitted content is concatenated directly into the HTML output. An attacker can submit JavaScript in either the author name or review body, such as `<img src=x onerror=alert(1)>`, which will execute in the browser when the page is rendered.

The fix uses `htmlspecialchars()` with `ENT_QUOTES` to escape all special characters, preventing the injected script tags from being interpreted as HTML. The `UTF-8` charset parameter ensures proper encoding. This transforms dangerous input like `<script>` into `&lt;script&gt;`, rendering it as literal text rather than executable code.
