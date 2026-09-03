## Verdict

Confirmed XSS (CWE-79): Untrusted user input from `$request['description']` flows through the presenter without sanitization and is rendered using Blade's raw output syntax `{!! !!}`, bypassing auto-escaping and allowing script injection.

## Source

The vulnerability spans three files in the call chain:

1. **TicketController.php (line 11)**: `$request['description']` is untrusted user input passed directly from the HTTP request
2. **TicketPresenter.php (line 9)**: The presenter maps `$ticket['description']` to `'descriptionHtml'` without any sanitization or validation
3. **show.blade.php (line 3)**: The template renders `$ticket['descriptionHtml']` using `{!! !!}`, which bypasses Laravel Blade's auto-escaping

Data flow: `$request['description']` → `$ticket['description']` → `$ticket['descriptionHtml']` → `{!! !!}` raw output

## Fix

**Option 1: Use Blade auto-escaping (recommended - no dependencies)**

Replace line 3 in `show.blade.php`:
```blade
<!-- Before -->
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>

<!-- After -->
<div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

The `{{ }}` syntax automatically applies `htmlspecialchars()` with appropriate flags, encoding all HTML special characters so user input is rendered as text rather than executable code.

**Option 2: Sanitize HTML if rich text is genuinely required**

If the application intentionally needs to support a subset of safe HTML tags (like `<b>`, `<i>`, `<a>`), sanitize in the presenter before rendering:

In `TicketPresenter.php`, add sanitization:
```php
<?php

require_once 'vendor/autoload.php';

final class TicketPresenter
{
    public function present(array $ticket): array
    {
        $purifier = new \HTMLPurifier();
        return [
            'title' => $ticket['title'],
            'descriptionHtml' => $purifier->purify($ticket['description']),
        ];
    }
}
```

Add the dependency: `composer require ezyang/htmlpurifier`

Then keep the Blade template as-is with `{!! !!}` since the HTML is now guaranteed safe.

## Explanation

The vulnerability arises because:

1. **Untrusted source**: `$request['description']` comes directly from user input without validation
2. **No sanitization in flow**: The TicketPresenter passes it through unchanged, and the field name `descriptionHtml` is misleading - it is not sanitized HTML but raw user input
3. **Raw output sink**: Blade's `{!! !!}` syntax is a documented escape bypass designed for pre-sanitized content. When applied to untrusted data, it allows attackers to inject scripts like `<img src=x onerror="alert('XSS')">` or `<script>alert('XSS')</script>`

According to CWE-79 PHP guidance, the default template auto-escaping (`{{ }}`) is the primary defence, and raw output bypasses like `{!! !!}` are safe only over already-sanitized input from a dedicated sanitization library.

## Behaviour changes

**With Option 1 (auto-escaping):**
- User input containing HTML tags like `<b>bold</b>` will display literally as text: `&lt;b&gt;bold&lt;/b&gt;`
- Scripts cannot execute because special characters are encoded
- Legitimate text containing `<`, `>`, `&`, and quotes renders correctly and safely

**With Option 2 (sanitized HTML):**
- Whitelisted HTML tags like `<b>`, `<i>`, `<a href="...">` render as formatted text
- Dangerous attributes like `onerror`, `onclick` are stripped regardless of tag
- Event handlers and script tags are removed, only safe markup survives
- Legitimate formatted content displays while malicious payloads are neutralized
