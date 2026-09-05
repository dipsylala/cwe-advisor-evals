## Verdict
Exploitable

## Source
Untrusted user input from POST parameters `$_POST['author']` (line 7) and `$_POST['body']` (line 8) is concatenated directly into HTML markup without any encoding.

## Fix

**Vulnerable code:**
```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . $review['author'] . '</h3>';  // No encoding
    $html .= '<p class="review-body">' . $review['body'] . '</p>';        // No encoding
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();
echo $card;  // Sink: unencoded data output
```

**Fixed code:**
```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();
echo $card;
```

## Explanation
The vulnerability occurs because user-submitted review data from `$_POST` is concatenated directly into HTML markup and echoed without encoding. An attacker can inject malicious script tags or event handlers by submitting specially crafted input (e.g., `"><script>alert('XSS')</script>` as the author name), which will execute in victims' browsers. The fix applies `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` flags and explicit UTF-8 encoding to neutralize special characters before they are output. This converts dangerous metacharacters like `<`, `>`, `"`, and `'` into HTML entities (`&lt;`, `&gt;`, `&quot;`, `&#039;`), preventing the injected content from breaking out of the HTML context and executing as code. The `ENT_SUBSTITUTE` flag ensures invalid UTF-8 sequences are converted to a replacement character rather than silently dropped, maintaining data visibility for debugging.

## Behaviour changes
None. The fixed code produces identical output as intended by the original code for all legitimate input. Benign HTML characters in user reviews (e.g., "Smith's Bakery", "5 < 10 stars") are properly preserved and rendered in the page while malicious markup is safely escaped.
