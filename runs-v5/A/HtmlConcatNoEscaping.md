## Verdict

Confirmed. `renderReviewCard()` concatenates `$review['author']` and `$review['body']` — both sourced directly from `$_POST` in `fetchSubmittedReview()` — into an HTML string with no escaping, and that string is echoed to the response. An attacker submitting a review with a payload such as `<script>...</script>` or an `onerror`-bearing tag in the `author` or `body` field gets it rendered verbatim in the page, executing in the browser of anyone who views the review card. This is reflected/stored XSS depending on how the review is persisted and later displayed.

## Source

`e:/Github/cwe-advisor/evals/cases/79/php/HtmlConcatNoEscaping/HtmlConcatNoEscaping.php`

- Line 7: `$_POST['author']`
- Line 8: `$_POST['body']`
- Line 16-17: unescaped concatenation into the `$html` string
- Line 26: `echo $card` — the sink where the unescaped markup reaches the response

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

    $author = htmlspecialchars($review['author'], ENT_QUOTES, 'UTF-8');
    $body = htmlspecialchars($review['body'], ENT_QUOTES, 'UTF-8');

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . $author . '</h3>';
    $html .= '<p class="review-body">' . $body . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();

echo $card;
```

## Explanation

`htmlspecialchars()` with `ENT_QUOTES` encodes `<`, `>`, `&`, `"`, and `'` so any markup or attribute-breaking characters in the reviewer-supplied `author` and `body` values are rendered as inert text rather than parsed as HTML. Encoding is applied at the point each value is placed into the markup (inside `renderReviewCard()`, right before concatenation), which is the correct place to neutralize output regardless of where the string later ends up — echoed directly here, but the same encoded value would remain safe if reused elsewhere. `ENT_QUOTES` is specified explicitly because both values are placed inside element content, not attributes, but using it consistently avoids a gap if the markup is later restructured to place either value inside a `"..."`-quoted attribute. The `UTF-8` charset argument is set explicitly since PHP's default encoding for `htmlspecialchars()` has varied across versions and an incorrect charset can cause the function to fail to encode certain byte sequences. No other behavior of the function changes: it still builds and returns the same HTML structure, just with the two untrusted fields rendered as literal text instead of executable markup.
