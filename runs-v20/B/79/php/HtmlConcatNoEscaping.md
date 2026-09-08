## Verdict

exploitable

## Source

`$_POST['author']` and `$_POST['body']`, read in `fetchSubmittedReview()` (lines 7-8) with no validation or encoding.

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

`fetchSubmittedReview()` reads `$_POST['author']` and `$_POST['body']` directly from the request with no encoding. `renderReviewCard()` concatenates both values straight into an HTML string (lines 16-17), which reaches the browser unescaped via `echo $card` at line 26 - an attacker-controlled review author or body can inject `<script>`, an event-handler attribute, or any other markup that executes in the viewing user's browser. The fix wraps each value in `htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8')` at the point of concatenation, which is the sink's actual context (HTML body text between tags). `ENT_QUOTES` encodes both single and double quotes so the value cannot break out of a surrounding quoted attribute if the markup is later restructured; `ENT_SUBSTITUTE` replaces invalid UTF-8 byte sequences with a placeholder character instead of silently discarding the whole string; explicit `ENT_HTML5` and `'UTF-8'` avoid relying on version-dependent defaults. This is output encoding at the sink, not input sanitization, so it does not alter what a legitimate reviewer can type - it only changes how special characters are represented in the generated HTML.

## Behaviour changes

- `<`, `>`, `&`, `"`, and `'` in a submitted author name or review body now render as their HTML entity equivalents (e.g. `&lt;`, `&amp;`) instead of being interpolated as raw markup. This is the intended effect of closing the weakness: the browser displays the literal characters the reviewer typed rather than parsing them as tags or attributes.
- No other behaviour changed: `fetchSubmittedReview()`'s return shape, the `??  ''` defaulting for missing POST fields, the HTML structure, and `echo $card` are unchanged.

## Verification

`php -l` on the fixed file: "No syntax errors detected". Also executed the fixed file directly with `$_POST['author'] = '<script>alert(1)</script>'` and `$_POST['body'] = 'Great "product" & fast <b>delivery</b>'` set before inclusion: output rendered `&lt;script&gt;alert(1)&lt;/script&gt;` in the author field (payload neutralized, non-executable) and `Great &quot;product&quot; &amp; fast &lt;b&gt;delivery&lt;/b&gt;` in the body field (legitimate special characters preserved and correctly encoded, not dropped). `htmlspecialchars()` is a PHP standard-library function, no new import required.
