## Verdict

Exploitable. The vulnerability presents an unbroken path from untrusted user input to unescaped HTML output.

## Source

`TicketController::show()` receives `$request['description']` (user-controlled input) at line 11 of TicketController.php.

## Fix

**Vulnerable code** (show.blade.php, line 3):
```blade
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```

**Option A - Simplest (no new dependencies):**
Replace the raw output syntax with escaped output:
```blade
<div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

**Option B - If HTML markup must be rendered (recommended by guidance):**

Install `mews/purifier` (Laravel wrapper for HTML Purifier):
```
composer require mews/purifier
```

Modify TicketPresenter.php, line 9:
```php
<?php

final class TicketPresenter
{
    public function present(array $ticket): array
    {
        return [
            'title' => $ticket['title'],
            'descriptionHtml' => \Purifier::clean($ticket['description'], 'default'),
        ];
    }
}
```

Keep the template as:
```blade
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```

## Explanation

The vulnerability exists because line 3 of show.blade.php uses Blade's raw output syntax `{!! !!}`, which bypasses automatic escaping. The value `$ticket['descriptionHtml']` flows from untrusted user input in `$request['description']` through TicketController to TicketPresenter, where it is renamed to 'descriptionHtml' but never validated or sanitized. This allows an attacker to inject arbitrary HTML and JavaScript that will execute in victims' browsers.

**Option A** uses Blade's `{{ }}` syntax to enable automatic HTML escaping, which neutralizes special characters (`<`, `>`, `&`, quotes) before rendering, preventing script injection. This is appropriate if the description should be plain text or text with no structural markup.

**Option B** sanitizes the HTML before assignment in the presenter using HTML Purifier, which strips dangerous elements and attributes while allowing safe markup (e.g., `<b>`, `<em>`, `<p>`). This preserves intentional HTML formatting while blocking injection vectors. According to CWE-79 guidance for PHP, raw Blade output `{!! !!}` is safe only over already-sanitized input.

## Behaviour changes

**Option A:** 
- Changed output from unescaped raw HTML to HTML-escaped text
- HTML tags in the description (if any) will now render as visible text rather than as markup
- Consequence: Rich text formatting is no longer rendered, but XSS injection is eliminated

**Option B:**
- Added a runtime dependency: `mews/purifier`
- HTML sanitization occurs once per request in the presenter
- Only safe HTML tags and attributes are preserved; dangerous ones are stripped
- Consequence: Performance overhead is minimal (sanitization is fast); rich text formatting is preserved while malicious attributes are removed; maintaining the allowlist of safe tags may require future updates as attack vectors evolve
