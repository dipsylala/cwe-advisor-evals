## Verdict
Confirmed. The code concatenates unsanitized POST parameters directly into HTML output, enabling reflected XSS via the author and body fields.

## Source
Lines 7-8: `$_POST['author']` and `$_POST['body']` are user-controlled.

## Fix
### File: HtmlConcatNoEscaping.php
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
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();

// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo $card;
```

## Explanation
The fix applies `htmlspecialchars()` with `ENT_QUOTES` flag to both user-supplied values before HTML concatenation. This escapes `<`, `>`, `&`, `"`, and `'` to their entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), preventing the browser from interpreting malicious script tags or event handlers. The `UTF-8` charset parameter ensures correct encoding for international characters.
