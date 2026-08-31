## Verdict

Exploitable. Untrusted user input from `$_POST['author']` and `$_POST['body']` is concatenated directly into HTML markup and echoed to the page without any encoding, allowing an attacker to inject malicious JavaScript via `<script>` tags or event handlers.

## Source

`$_POST['author']` and `$_POST['body']` are captured in `fetchSubmittedReview()` at lines 7-8. These values flow through `renderReviewCard()` where they are concatenated unencoded into the `$html` string at lines 16-17. The constructed HTML is then returned and echoed at line 26.

## Fix

```php
// Vulnerable code (lines 16-17):
$html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
$html .= '<p class="review-body">' . $review['body'] . '</p>';

// Fixed code:
$html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</h3>';
$html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

## Explanation

`htmlspecialchars()` with the flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit UTF-8 encoding converts HTML special characters (`<`, `>`, `&`, `"`, `'`) to their named entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`). This ensures the browser treats the data as text content, not executable HTML or JavaScript. The `ENT_QUOTES` flag escapes both single and double quotes, preventing attribute breakout. `ENT_SUBSTITUTE` replaces invalid UTF-8 sequences with the replacement character rather than silently dropping them. The explicit UTF-8 charset ensures correct encoding on systems with different default character sets.

## Behaviour changes

None. The escaping preserves the original text content while eliminating the injection vector. Legitimate content containing `<`, `>`, `&`, and quotes will still render correctly as visible text.
