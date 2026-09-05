## Verdict

CONFIRMED: CWE-79 XSS via unescaped Blade output of untrusted user input.

## Source

`TicketController::show()` receives untrusted `$request['description']` from the caller and passes it through `TicketPresenter::present()` unchanged, which assigns it to `$ticket['descriptionHtml']`. The presenter does not sanitize or encode this data.

## Fix

**Blade template (line 3): Change from raw to auto-escaped output**

```blade
<!-- BEFORE (VULNERABLE): -->
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>

<!-- AFTER (FIXED): -->
<div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

The `{{ }}` syntax enables Blade's built-in auto-escaping, which applies `htmlspecialchars()` with appropriate flags, encoding HTML metacharacters so untrusted input renders as text, not executable code.

## Explanation

The vulnerability occurs because `{!! !!}` (Blade's raw output syntax) bypasses HTML escaping entirely, assuming the value contains safe, pre-sanitized HTML. However, `$ticket['descriptionHtml']` is populated directly from untrusted user input (`$request['description']`) with no sanitization step. An attacker can inject `<script>alert('XSS')</script>` or event handlers like `<img onerror=...>` and have them execute in victims' browsers.

Switching to `{{ }}` enables Blade's automatic HTML context-aware escaping, which neutralizes the injection by converting metacharacters (`<`, `>`, `&`, `"`, `'`) into HTML entities, rendering them harmless.

This assumes the field is meant to display plain text. If rich HTML truly needs to render, the data must be sanitized through a library like `mews/purifier` (Laravel's HTML Purifier wrapper) or Symfony's `HtmlSanitizer` before reaching the template, and only then passed to `{!! !!}`.

## Behaviour changes

- Line 3: Untrusted user text that previously could inject scripts now renders as escaped HTML entity sequences, displaying literally.
- Legitimate content containing `<`, `&`, or quotes (e.g., "Alice & Bob's meeting < 3pm") now displays with those characters visibly escaped in the browser (e.g., "Alice &amp; Bob's meeting &lt; 3pm"), not as HTML metacharacters.
- XSS payloads are neutralized: `<script>alert('XSS')</script>` displays as text, not executed.
