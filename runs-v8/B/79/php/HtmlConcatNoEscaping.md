## Verdict

Exploitable. Untrusted user input from `$_POST['author']` and `$_POST['body']` is concatenated directly into HTML without encoding and echoed to the browser, allowing script injection.

## Source

Lines 7-8: `$_POST['author']` and `$_POST['body']` are untrusted user inputs from a form submission.

Lines 16-17: These values are concatenated directly into HTML strings without any encoding.

Line 26: The unescaped HTML is output via `echo`, sending it to the client browser without any protective encoding.

## Fix

Apply `htmlspecialchars()` with explicit flags at each output sink.

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

`htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and `'UTF-8'` encoding converts special characters (`<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents (`&lt;`, `&gt;`, `&quot;`, `&#039;`, `&amp;`), rendering any injected script tags and event handlers as literal text rather than executable code. The flags are specified explicitly: `ENT_QUOTES` escapes both double and single quotes (necessary to prevent attribute breakout), `ENT_SUBSTITUTE` converts invalid UTF-8 sequences to the Unicode replacement character, and `ENT_HTML5` ensures HTML5 entity compatibility. This encoding is applied at the point where data enters the HTML body context (the concatenation), so the safe value flows through to the `echo` statement.

## Behaviour changes

Users can now submit reviews containing `<`, `>`, `"`, `'`, and `&` characters. These characters will render as text in the displayed review card rather than being interpreted as HTML markup or JavaScript. For example, a review submission of `"Great & affordable!"` will display as `"Great &amp; affordable!"` in the HTML source but render visually as `"Great & affordable!"` in the browser. Legitimate content containing angle brackets (e.g., `<3`) or ampersands will also be visible and safe.
