## Verdict

Confirmed. `renderReviewCard()` concatenates `$review['author']` and `$review['body']` directly into an HTML string with no encoding, and `echo $card;` writes that string to the response. Both fields originate from `$_POST`, so an attacker-supplied review author or body containing `<script>` or an event-handler attribute is rendered as live markup in the storefront page, producing a stored/reflected XSS sink at line 26.

## Source

- `fetchSubmittedReview()` reads `$_POST['author']` and `$_POST['body']` (lines 7-8) with no validation or encoding, returning them as `$review['author']` / `$review['body']`.
- `renderReviewCard()` concatenates both values straight into the `<h3>` and `<p>` markup (lines 16-17).
- `echo $card;` (line 26) is the sink that writes the unescaped, attacker-controlled HTML into the response.

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

`htmlspecialchars()` with `ENT_QUOTES` encodes `<`, `>`, `&`, `"`, and `'` into their HTML entity equivalents, so a submitted value such as `<script>alert(1)</script>` or `" onmouseover="alert(1)` renders as inert text inside the `<h3>`/`<p>` elements instead of being parsed as markup or breaking out of an attribute. `ENT_QUOTES` is included even though the values here sit in element content rather than an attribute, so the encoding stays safe if either field is later moved into an attribute context. The `'UTF-8'` charset argument is specified explicitly rather than relying on `php.ini`'s default, since PHP versions before 8.1 default `htmlspecialchars()` to `ISO-8859-1` if no encoding is given.

The encoding is applied once, at the point where the trusted HTML template is built (`renderReviewCard()`), rather than at the source (`fetchSubmittedReview()`) — keeping the raw submitted values available for any non-HTML use (e.g. storage, logging, or a JSON API) while ensuring every HTML output path encodes correctly for its context. No other behavior changes: legitimate author names and review text (including punctuation, apostrophes, and multi-byte characters) render unchanged, since `htmlspecialchars()` only transforms the five characters with special meaning in HTML.
