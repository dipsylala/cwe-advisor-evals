## Verdict
Confirmed CWE-79. User-supplied review data from `$_POST` is concatenated into HTML and echoed without escaping, allowing JavaScript injection.

## Source
```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
    $html .= '<p class="review-body">' . $review['body'] . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();
echo $card;
```

The vulnerability is in lines 16-17 where `$review['author']` and `$review['body']` are concatenated into HTML without escaping. An attacker can inject malicious scripts via the review form.

## Fix
Escape the user input using `htmlspecialchars()` with `ENT_QUOTES` flag before inserting into HTML:

```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();
echo $card;
```

## Explanation
`htmlspecialchars()` with `ENT_QUOTES` converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entity equivalents, preventing the browser from interpreting user input as executable code. The `UTF-8` charset parameter ensures correct encoding. This is the primary XSS defence for HTML context output in PHP.
