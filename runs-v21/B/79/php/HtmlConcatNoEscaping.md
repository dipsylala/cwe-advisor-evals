## Verdict

Exploitable. Untrusted POST data from `$_POST['author']` and `$_POST['body']` flows directly into HTML concatenation without encoding, allowing XSS injection through the echo at line 26.

## Source

Untrusted input: `$_POST['author']` and `$_POST['body']` (lines 7-8) are retrieved directly from the HTTP request via `fetchSubmittedReview()` with no validation or encoding.

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
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();

// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo $card;
```

## Explanation

The fix applies `htmlspecialchars()` with explicit flags (`ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5`) and UTF-8 encoding to both `$review['author']` and `$review['body']` at lines 16-17. These calls encode HTML special characters: `<` becomes `&lt;`, `>` becomes `&gt;`, `&` becomes `&amp;`, double quotes become `&quot;`, and single quotes become `&#039;`. This neutralizes any attempt to inject script tags, event handlers, or other malicious markup via the form input. The flags ensure complete coverage: `ENT_QUOTES` encodes both double and single quotes, `ENT_SUBSTITUTE` replaces invalid UTF-8 sequences with the replacement character rather than silently dropping them, and `ENT_HTML5` follows HTML5 standards. The explicit flags prevent reliance on PHP version defaults, which changed in PHP 8.1.

## Behaviour changes

None. The function still concatenates the same HTML structure and returns it intact. The only change is encoding the user-supplied values before concatenation, which preserves the application's output and semantics (special characters in the text render correctly as their literal representation) while eliminating the injection vector.
