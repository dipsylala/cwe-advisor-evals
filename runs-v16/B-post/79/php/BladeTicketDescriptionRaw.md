## Verdict

Exploitable. User-controlled data from `$request['description']` flows through TicketPresenter directly to a Blade template and is rendered as raw HTML without escaping or sanitization.

## Source

`$request['description']` in TicketController.php (line 11) — untrusted HTTP request parameter, passed without validation to `TicketPresenter::present()`.

## Fix

**Vulnerable code** (show.blade.php, line 3):
```blade
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```

**Fixed code**:
```blade
<div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

## Explanation

The fix replaces Blade's raw output syntax `{!! !!}` with automatic output escaping `{{ }}`. Blade's double-brace syntax applies HTML entity encoding by default, converting `<`, `>`, `&`, `"`, and `'` to their HTML entity equivalents. This prevents injected script tags and event handlers from executing while preserving the display of special characters in legitimate content. The data source remains the same; only the output encoding changes.

## Behaviour changes

This change alters rendering of content containing special characters:
- Input: `<script>alert('xss')</script>` now renders as `&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;` (displayed as text, not executed)
- Input: `Q&A Support` now renders correctly as `Q&amp;A Support`
- Any literal `<` or `>` characters in the description text will be escaped and displayed as encoded entities rather than interpreted as HTML markup

If the application truly requires rendering rich HTML content in the description field, the proper fix requires sanitization: sanitize the description through an HTML allowlist validator (Laravel Purifier package `mews/purifier` or `ezyang/htmlpurifier`) in TicketPresenter before passing it to the template, then keep the raw output syntax. This approach is more complex but preserves intentional HTML formatting while blocking malicious tags.
