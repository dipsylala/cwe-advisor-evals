## Verdict

CWE-79 (Cross-Site Scripting) - **exploitable**. Confidence: high.

- Location: `HtmlConcatNoEscaping.php`, line 26 (`echo $card;`)
- Root cause: unescaped concatenation at lines 16-17, inside `renderReviewCard()`

## Source

`$_POST['author']` and `$_POST['body']`, read in `fetchSubmittedReview()` (lines 7-8) with no validation or encoding, and returned as-is in the `$review` array.

Data flow: `fetchSubmittedReview()` returns raw POST values -> `renderReviewCard()` concatenates `$review['author']` and `$review['body']` directly into the `$html` string (lines 16-17) -> the built string is returned as `$card` (line 20/23) -> `echo $card;` writes it to the HTTP response (line 26).

Nothing in this path validates, encodes, or otherwise constrains the values between the `$_POST` read and the `echo`, so an attacker-supplied review author or body reaches the browser byte-for-byte. A submission such as `author = <img src=x onerror=alert(document.cookie)>` executes in the context of any visitor who views the product page's reviews.

## Fix

Vulnerable code:

```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . $review['author'] . '</h3>'; // unescaped: attacker-controlled HTML injected verbatim
    $html .= '<p class="review-body">' . $review['body'] . '</p>';       // unescaped: attacker-controlled HTML injected verbatim
    $html .= '</div>';

    return $html;
}
```

Fixed code:

```php
function renderReviewCard() {
    $review = fetchSubmittedReview();

    $html = '<div class="review-card">';
    $html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</h3>';
    $html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
    $html .= '</div>';

    return $html;
}
```

`fetchSubmittedReview()` and the `echo $card;` call site are unchanged; only the two concatenation lines inside `renderReviewCard()` are affected.

## Explanation

Both untrusted fields are now passed through `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and an explicit `'UTF-8'` charset at the point they are written into the HTML body, which is the sink identified by the data-flow trace. `ENT_QUOTES` encodes both single and double quotes so the values cannot break out of the surrounding `<h3>`/`<p>` markup even if an attacker later moves them into an attribute; `ENT_SUBSTITUTE` replaces malformed UTF-8 byte sequences with a Unicode replacement character instead of silently dropping the whole string, which would otherwise mask malformed input rather than encode it; `ENT_HTML5` selects the HTML5 entity set matching the target document type. Encoding is applied per-sink, at each of the two concatenation points, rather than once on input, consistent with the general and PHP-specific guidance (`cwe/79/INDEX.md`, `cwe/79/php/INDEX.md`). This closes the injection: any `<`, `>`, `&`, or quote characters submitted as a review author or body are rendered as their literal text/entity form and can no longer be interpreted as markup or script by the browser.

## Behaviour changes

- Author and body text containing `<`, `>`, `&`, `"`, or `'` now renders as HTML entities instead of being interpreted as markup - this is the intended effect of the fix, not a regression. Plain-text reviews (the overwhelming common case) render identically to before.
- No change to the function's return type, the caller's use of `$card`, the `echo` call, or any other part of the sink contract: `renderReviewCard()` still returns a string, `fetchSubmittedReview()` is untouched, and no arguments, defaults, or failure behavior were altered.
- Assumption: the review card is rendered as HTML body content (not inside an attribute, `<script>` block, or URL), based on the `<h3>`/`<p>` wrapping tags already present in the code, so HTML-body encoding (`htmlspecialchars`) is the correct context-specific encoding here.
