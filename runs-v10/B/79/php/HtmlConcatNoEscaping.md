## Verdict

Exploitable. Untrusted `$_POST` input flows directly into HTML output without encoding, allowing script injection.

## Source

`$_POST['author']` and `$_POST['body']` (lines 7-8) - user-supplied form data with no validation or sanitization.

## Fix

**Vulnerable code (lines 16-17):**
```php
$html .= '<h3 class="review-author">' . $review['author'] . '</h3>';
$html .= '<p class="review-body">' . $review['body'] . '</p>';
```

**Fixed code:**
```php
$html .= '<h3 class="review-author">' . htmlspecialchars($review['author'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</h3>';
$html .= '<p class="review-body">' . htmlspecialchars($review['body'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . '</p>';
```

## Explanation

The vulnerable code concatenates user-supplied review author and body text directly into HTML output. An attacker can submit a review with content like `<script>alert('XSS')</script>` or event handlers such as `" onclick="alert('XSS')`, which will execute in the victim's browser when the review page is rendered.

The fix applies `htmlspecialchars()` to both values at the point of output, encoding HTML special characters (`<`, `>`, `&`, `"`, `'`) into their entity forms (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`). This converts attacker input from executable code back to displayable text data. The flags are: `ENT_QUOTES` escapes both double and single quotes (necessary for attribute context), `ENT_SUBSTITUTE` replaces invalid UTF-8 with the replacement character (preventing silent data loss), and `ENT_HTML5` uses HTML5 entity names (current standard).

## Behaviour changes

None. `htmlspecialchars()` converts reserved characters to their HTML entity equivalents, allowing the original content to display correctly while preventing script execution. Legitimate review text containing `<`, `>`, `&`, or quotes will render visually correct (e.g. "Rock & Roll" displays as "Rock &amp; Roll" but appears as "Rock & Roll" in the browser).
