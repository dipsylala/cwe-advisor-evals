## Verdict

- **CWE ID**: CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting)
- **Location**: `resources/views/tickets/show.blade.php`, line 3
- **Verdict**: exploitable
- **Confidence**: high

## Source

- **Source**: `$request['description']` in `TicketController::show()` (`TicketController.php` line 11) - an HTTP-request-derived array value with no validation, encoding, or sanitization applied at any point.
- **Data flow**: `TicketController::show()` copies `$request['description']` verbatim into `$ticket['description']` and passes the array to `TicketPresenter::present()` (`TicketController.php` line 14). `TicketPresenter::present()` copies the value unchanged into the `descriptionHtml` key (`TicketPresenter.php` line 9) - it performs no HTML sanitization despite the key's name. `show.blade.php` then renders `$ticket['descriptionHtml']` at line 3.
- **Sink**: `{!! $ticket['descriptionHtml'] !!}` - Laravel Blade's raw/unescaped output directive. This bypasses Blade's automatic `htmlspecialchars`-based escaping and writes the value directly into the HTML body of the `<div class="ticket-description">` element.
- No sanitization, allowlist, or HTML-purifying step exists anywhere on this path, so any HTML or `<script>` content placed in the ticket description request field is rendered as live markup in the victim's browser (stored/reflected XSS depending on how the request payload is persisted upstream).

## Fix

Vulnerable code (`resources/views/tickets/show.blade.php`):

```blade
<article class="ticket">
  <h1>{{ $ticket['title'] }}</h1>
  <div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
</article>
```

Fixed code:

```blade
<article class="ticket">
  <h1>{{ $ticket['title'] }}</h1>
  <div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
</article>
```

The single-line change is replacing the raw-output directive `{!! ... !!}` with Blade's escaping directive `{{ ... }}` at line 3, so the description passes through Blade's `e()` helper (`htmlspecialchars` with `ENT_QUOTES`, UTF-8) before being written into the page.

## Explanation

The description value is attacker-controlled from the moment it enters `TicketController::show()` and is never validated, encoded, or run through an HTML sanitizer (e.g. HTML Purifier) anywhere in the call chain - `TicketPresenter::present()` only renames the key to `descriptionHtml`, which does not make the underlying string trustworthy HTML. Because the Blade template renders it with `{!! !!}`, that raw string is emitted directly into the page's HTML, so a description containing `<script>` or an event-handler attribute executes in the viewing user's browser. Switching the sink to `{{ }}` applies Blade's default HTML-entity encoding, which neutralizes `<`, `>`, `&`, `"`, and `'` so the value is always rendered as inert text rather than markup. This is the correct fix here because nothing upstream sanitizes the value into safe HTML; if the product genuinely needs to let ticket descriptions contain limited rich HTML, the untrusted string would first need to pass through a dedicated sanitizer such as `mews/purifier` (Laravel) before a raw-output directive could be used safely, and no such step exists in this chain.

## Behaviour changes

- Ticket descriptions containing HTML metacharacters (`<`, `>`, `&`, quotes) will now render as literal visible text instead of being interpreted as markup. For plain-text ticket descriptions (the field's evident intent, given `TicketController` sources it as ordinary request input with no sanitization step), output is visually identical before and after the fix.
- No arguments, return values, or control flow elsewhere in the chain change; the fix is confined to the output-encoding directive at the sink identified in the trace.
- Assumption: the `descriptionHtml` key name suggests an original intent to allow rich HTML, but since no sanitization exists anywhere in `TicketController` or `TicketPresenter`, the value must be treated as plain untrusted text rather than pre-sanitized markup; the resolution is to escape it, not to introduce an unreviewed HTML-sanitization dependency as part of this fix.
