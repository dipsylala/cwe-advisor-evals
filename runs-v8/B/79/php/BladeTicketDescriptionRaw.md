## Verdict

Exploitable. Untrusted user input from `$request['description']` flows directly through the TicketController and TicketPresenter to a Blade raw output sink without any sanitization or validation.

## Source

`$request['description']` in TicketController::show() - user-supplied via HTTP request.

Data flows through:
1. TicketController.show() receives `$request['description']` and stores it in `$ticket['description']`
2. TicketPresenter.present() aliases it as `descriptionHtml` without sanitization
3. show.blade.php renders it with `{!! !!}` (raw/unescaped output)

## Fix

**Vulnerable code (line 3):**
```blade
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```

**Fixed code:**
```blade
<div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

## Explanation

The vulnerability occurs because user-controlled description text is rendered using Blade's raw output syntax `{!! !!}`, which bypasses Laravel's auto-escaping and outputs untrusted data directly into the HTML. An attacker can inject malicious scripts that execute in victims' browsers. Changing `{!! !!}` to `{{ }}` enables Blade's built-in auto-escaping, which applies `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` flags, converting `<`, `>`, `"`, and `'` to HTML entities. This prevents injection while preserving legitimate content structure.

## Behaviour changes

HTML special characters in the description will now be escaped in the rendered output (e.g., `<script>` renders as `&lt;script&gt;`). This prevents script injection but means if descriptionHtml legitimately needs to display HTML markup (e.g., formatted text with `<b>`, `<em>` tags), that markup will be rendered as escaped text rather than formatted HTML. If rich HTML rendering is genuinely required, the TicketPresenter should sanitize the input using an HTML purification library (e.g., `mews/purifier`) with a tag allowlist before assigning it to descriptionHtml, then the raw output could be justified.
