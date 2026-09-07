## Verdict

**CWE-79**: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)

The vulnerable code concatenates unescaped POST parameters directly into an HTML string, allowing attackers to inject arbitrary HTML and JavaScript that executes in the browser. The fix applies `htmlspecialchars()` with context-appropriate flags to all untrusted values before rendering.

## Source

**Untrusted inputs**: `$_POST['author']` and `$_POST['body']` from the HTTP request

**Data flow**:
1. `fetchSubmittedReview()` retrieves raw POST parameters: `$_POST['author']` and `$_POST['body']`
2. `renderReviewCard()` concatenates these values directly into an HTML string without encoding at lines 16-17
3. The concatenated string is returned and echoed at line 26

**Sink**: `echo $card` at line 26 renders the unescaped HTML to the browser

**Exploitability**: An attacker can submit POST data containing HTML/JavaScript:
- `author=<img src=x onerror=alert('XSS')>`
- `body=<script>alert('XSS')</script>`

The browser will execute the injected scripts, compromising the victim's session.

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

The fix applies `htmlspecialchars()` with flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit encoding `'UTF-8'` to both `$review['author']` and `$review['body']` before concatenating them into the HTML string.

**What this does**:
- `htmlspecialchars()` converts HTML metacharacters to named entities: `<` becomes `&lt;`, `>` becomes `&gt;`, `"` becomes `&quot;`, `'` becomes `&#039;`, and `&` becomes `&amp;`
- `ENT_QUOTES` ensures both double and single quotes are escaped, preventing breakout from attributes
- `ENT_SUBSTITUTE` replaces invalid UTF-8 sequences with the replacement character rather than silently dropping them
- `ENT_HTML5` uses the HTML5 character set, covering the full range of entities
- Explicit `'UTF-8'` ensures consistent encoding across all environments

**Why this closes the vulnerability**: After encoding, any attempt to inject HTML or JavaScript appears as literal text rather than executable code. `<script>alert(1)</script>` becomes `&lt;script&gt;alert(1)&lt;/script&gt;`, which renders as harmless text in the browser.

**Sink contract**: `echo` expects a string and sends it to output. This fix preserves that contract while ensuring the string contains no unencoded dangerous characters.

## Behaviour changes

**User-visible changes**: Special characters in author names and review bodies now render as HTML entities when displayed. For example, a user name containing `<` will display as `&lt;`. This is correct and expected behaviour—legitimate content containing angle brackets or quotes still displays readably in the browser, just with entities visible in the HTML source.

**Security changes**: The application is no longer vulnerable to XSS injection. Payloads containing HTML/JavaScript are rendered as inert text instead of being executed.
