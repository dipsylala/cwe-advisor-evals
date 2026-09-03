## Verdict
The template incorrectly outputs user-controlled data without escaping, exposing the application to XSS attacks.

## Source
In `show.blade.php` line 3, user input flows from `TicketController::show()` → `TicketPresenter::present()` → the Blade template:

1. `TicketController` receives `$request['description']` (untrusted)
2. `TicketPresenter` passes it unchanged as `descriptionHtml`
3. The template outputs it with `{!! $ticket['descriptionHtml'] !!}`, which renders raw HTML without escaping

An attacker can inject `<script>alert('xss')</script>` or event handlers via the description field, and the script will execute in victims' browsers.

## Fix
Change line 3 of `show.blade.php` from:
```
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```
to:
```
<div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

The `{{ ... }}` syntax applies Blade's automatic escaping, converting HTML entities (`<` → `&lt;`, `>` → `&gt;`, etc.) so that user input renders as text rather than executable markup.

## Explanation
Blade templates treat `{{ ... }}` and `{!! ... !!}` differently: `{{ }}` escapes HTML by default, while `{!! !!}` outputs raw content. The variable name `descriptionHtml` is misleading—it suggests pre-rendered HTML, but the data actually comes directly from user input. The fix applies HTML entity encoding at the output boundary, which is the correct defence for XSS in templating. No changes to the controller or presenter are needed; the fix belongs at the sink (where the data exits to HTML).
