## Verdict

CONFIRMED. Untrusted input from `$request['description']` flows to an XSS sink without sanitization or encoding.

## Source

`TicketController.php` line 11: `$request['description']` is user-supplied HTTP request data, passed directly into the ticket array without validation or encoding.

## Fix

Replace Laravel Blade's raw output syntax `{!! !!}` with the auto-escaping syntax `{{ }}` in the template.

### File: resources/views/tickets/show.blade.php

```php
<article class="ticket">
  <h1>{{ $ticket['title'] }}</h1>
  <div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
</article>
```

## Explanation

The vulnerability occurs because `{!! !!}` is Blade's bypass for auto-escaping, intended only for already-sanitized HTML. The variable `$ticket['descriptionHtml']` contains untrusted user input from `$request['description']` without any sanitization, allowing XSS injection.

The fix uses `{{ }}` syntax, which invokes Laravel Blade's automatic output encoding (`htmlspecialchars()` with appropriate flags). This encodes special characters like `<`, `>`, `&`, and quotes to their HTML entity equivalents, converting any injected script tags into safe text that displays literally in the browser rather than executing.

## Behaviour changes

- User input containing `<script>alert('xss')</script>` will render as escaped text `&lt;script&gt;alert('xss')&lt;/script&gt;` instead of executing.
- Legitimate content containing `<`, `>`, `&` characters will display correctly as escaped entities.
- HTML markup in user descriptions will no longer be interpreted—it will display as text. If rich HTML support is actually required, the input must pass through a dedicated HTML sanitizer (e.g., `mews/purifier` with a tag allowlist) before assignment to `descriptionHtml`, and only then is `{!! !!}` safe to use.
