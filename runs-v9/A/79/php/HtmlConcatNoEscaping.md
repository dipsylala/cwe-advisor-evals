## Verdict

Confirmed. `renderReviewCard()` concatenates the reviewer-submitted `author` and `body` fields directly into an HTML string with no output encoding, and `echo $card` writes that string to the response. A review containing `<script>...</script>` or an `onerror` handler in either field executes in the browser of anyone who views the product page's reviews.

## Source

`$_POST['author']` and `$_POST['body']`, read in `fetchSubmittedReview()` (HtmlConcatNoEscaping.php lines 7-8) and passed unmodified into `renderReviewCard()`.

## Fix

```php
<?php
// Product review card renderer for a storefront product page.

function fetchSubmittedReview() {
    // Reviewer name and review text as submitted via the review form.
    return [
        'author' => $_POST['author'] ?? '',
        'body' => $_POST['body'] ?? ''
    ];
}

function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();

echo $card;
```

## Explanation

Both `author` and `body` are attacker-controlled request data that flow, unescaped, into an HTML context (element body content between `<h3>`/`<p>` tags). The fix applies `htmlspecialchars()` at the point each value is concatenated into the markup, converting `<`, `>`, `&`, and quote characters into their HTML entity equivalents so any markup the reviewer submits is rendered as inert text rather than parsed as tags or attributes.

`ENT_QUOTES` is included so both single and double quotes are encoded, which matters if this markup is later reused inside an HTML attribute; `ENT_SUBSTITUTE` prevents the function from returning an empty string when the input contains invalid UTF-8 byte sequences, which would otherwise silently drop content (or, in older default configurations, behave inconsistently). The explicit `'UTF-8'` charset argument avoids relying on the `default_charset` ini setting, which may not match the page's actual encoding.

Escaping is applied at render time (where the value is written into HTML) rather than at input time in `fetchSubmittedReview()`, so the stored/raw value stays usable if it is later needed in a non-HTML context (e.g. an API response, a database record, or a log entry) without double-encoding or losing the original characters. No allowlist or strip-tags approach is used because removing tags can still leave a value that is unsafe in a different context, and rejecting or stripping markup from a genuine review (e.g. "5 < 10 stars") would corrupt legitimate input; encoding preserves the exact text while making it non-executable.
