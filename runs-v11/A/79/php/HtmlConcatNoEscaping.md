## Verdict
**CWE-79 Confirmed**: User-supplied POST data is concatenated directly into HTML output without escaping, enabling stored or reflected XSS.

## Source
The vulnerability originates in the data flow:
1. **Source**: `$_POST['author']` and `$_POST['body']` (lines 7–8 in `fetchSubmittedReview()`)
2. **Flow**: Unescaped values assigned to `$review` array, then concatenated into `$html` string (lines 16–17)
3. **Sink**: `echo $card` (line 26) outputs unsanitized HTML to the response

An attacker can inject JavaScript in the `author` or `body` POST fields; the injected code executes in the browser of anyone viewing the review.

## Fix
Escape user input using `htmlspecialchars()` when concatenating into HTML:

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

Apply `htmlspecialchars()` with `ENT_QUOTES` flag (escapes both double and single quotes) and explicit UTF-8 charset to each POST value before embedding in HTML.

## Explanation
`htmlspecialchars()` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, preventing the browser from interpreting them as markup or script delimiters. The `ENT_QUOTES` flag ensures both attribute and content contexts are protected. This is the primary defense for reflected and stored XSS in PHP—all user input rendered in HTML must be context-escaped.
