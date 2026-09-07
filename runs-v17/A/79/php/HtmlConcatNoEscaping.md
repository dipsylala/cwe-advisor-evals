## Verdict
The vulnerability is confirmed. User-supplied data from POST parameters is concatenated directly into HTML output without escaping, enabling reflected XSS.

## Source
The `fetchSubmittedReview()` function retrieves unvalidated POST data and passes it to `renderReviewCard()`, which concatenates it into HTML. The HTML is then echoed directly to the response without sanitization.

**Data flow:**
- Input source: `$_POST['author']` and `$_POST['body']` (lines 7-8)
- Unsanitized concatenation into HTML: lines 16-17
- Taint sink: `echo $card` (line 26)

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
The fix applies output encoding using `htmlspecialchars()` at the point where user-controlled data is inserted into HTML context. The function converts special characters (`<`, `>`, `&`, `"`, `'`) into HTML entities, preventing the browser from interpreting injected markup or script tags as code.

The flags used are:
- `ENT_QUOTES`: Escapes both double and single quotes, protecting against attribute injection
- `'UTF-8'`: Explicitly specifies character encoding to match the document

This ensures that any characters in the user's input (author name, review text) are treated as literal text, not as HTML structure or code, while allowing the surrounding HTML tags to render normally.
