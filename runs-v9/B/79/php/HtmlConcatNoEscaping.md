## Verdict

exploitable (confidence: high)

## Source

`$_POST['author']` and `$_POST['body']` in `fetchSubmittedReview()` (lines 7-8) - both are attacker-controlled HTTP request fields with no validation or sanitization applied.

## Fix

Vulnerable code:

```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . $review['author'] . '</h3>'; // unescaped concatenation
    $html .= '<p class="review-body">' . $review['body'] . '</p>';       // unescaped concatenation
    $html .= '</div>';

    return $html;
}

$card = renderReviewCard();

// SAST FINDING: CWE-79 reported here. Sink is the next statement.
echo $card;
```

Fixed code:

```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $author = htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    $body = htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');

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

`$review['author']` and `$review['body']` flow from `$_POST` straight into an HTML string built by concatenation with no encoding, and that string is echoed as-is at line 26, so a submitted review containing markup (e.g. `<script>` or an `onerror` handler) executes in the browser of anyone who views the review card - a stored/reflected XSS sink. The fix HTML-encodes both fields at the point they are written into markup using `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and an explicit `'UTF-8'` charset, per the PHP-specific guidance: `ENT_QUOTES` neutralizes both single and double quotes so the value cannot break out of the surrounding `<h3>`/`<p>` element context, and `ENT_SUBSTITUTE` prevents a malformed UTF-8 byte sequence from silently dropping the whole value. This is the HTML-body context (data sits between tags, not inside an attribute or script block), so `htmlspecialchars()` alone is the correct and sufficient encoding here.

## Behaviour changes

None beyond closing the weakness. The function still returns the same `<div class="review-card">...</div>` structure via `echo`; the only difference is that `<`, `>`, `&`, `"`, and `'` characters within the author name or review body are now rendered as their HTML entity equivalents instead of being interpreted as markup - which is the intended and necessary effect of the fix, not a side effect. Legitimate review text containing no special characters renders identically to before.
