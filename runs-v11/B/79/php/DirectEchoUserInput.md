## Verdict

Exploitable. Untrusted `$_POST['note']` is concatenated directly into HTML output without encoding, allowing arbitrary script injection in the requester-note div.

## Source

Line 27: `$_POST['note']` — user-supplied POST parameter, untrusted external input.

## Fix

**Vulnerable code:**
```php
echo "<div class='requester-note'>Note from requester: " . $_POST['note'] . "</div>";
```

**Fixed code:**
```php
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($_POST['note'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . "</div>";
```

## Explanation

The fix applies `htmlspecialchars()` with the full flag set required by the PHP guidance. `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` together ensure that single quotes, double quotes, ampersands, and HTML5 entities are all escaped, preventing breakout from both the containing attribute and the HTML body text context. The explicit `'UTF-8'` encoding prevents silent truncation of multi-byte characters that could bypass the escaping. `ENT_SUBSTITUTE` (new in the recommendation) replaces invalid UTF-8 sequences with U+FFFD rather than dropping them, which exposes malformed input rather than hiding it. This encoding-at-sink approach neutralizes the injected script payload while preserving the semantic content for legitimate input.

## Behaviour changes

None. The fix preserves the `echo` contract: it produces the same HTML output structure, accepts the same input form, and returns nothing. The only change is encoding special characters to their HTML entities, which passes-through for plain text and prevents interpretation of metacharacters.
