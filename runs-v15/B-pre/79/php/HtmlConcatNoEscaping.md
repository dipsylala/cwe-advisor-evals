## Verdict

Exploitable. Untrusted user input from `$_POST['author']` and `$_POST['body']` is concatenated directly into HTML without escaping, then output via `echo`, allowing XSS injection.

## Source

POST parameters `$_POST['author']` and `$_POST['body']` (lines 7–8) serve as the untrusted data sources. They originate from user input via the review form and flow unchanged through `fetchSubmittedReview()` into the `renderReviewCard()` function.

## Fix

**Vulnerable code (lines 16–17):**
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

Each untrusted value is encoded using `htmlspecialchars()` with the flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and an explicit `'UTF-8'` charset. This encoding converts HTML metacharacters (`<`, `>`, `&`, `"`, `'`) into entity references, neutralizing script injection. The flags ensure both double and single quotes are escaped (preventing attribute breakout), invalid UTF-8 sequences become replacement characters (preventing silent data loss), and the encoding follows HTML5 semantics. This is applied at the output sink—where data enters HTML markup—making data safe for the browser to interpret as content, not code.

## Behaviour changes

None. The `htmlspecialchars()` function returns a string, preserving the concatenation and output chain. The encoded entities display as the original text in the browser (e.g., `<` renders as `<`), so legitimate review text with special characters remains readable. No changes to function signatures, return values, or downstream processing occur.
