## Verdict

Confirmed. Reflected cross-site scripting: the ticket description travels from the HTTP request to the Blade view with no encoding, through a presenter that mislabels the raw value as pre-escaped HTML.

## Source

`$request['description']` in `TicketController::show()` (TicketController.php line 11) is attacker-controlled HTTP request data. It is copied verbatim into the `$ticket['description']` array entry with no validation or encoding.

`TicketPresenter::present()` (TicketPresenter.php line 9) passes that same untouched value through under the key `descriptionHtml`, performing no sanitization despite the name implying the value is safe, ready-to-render HTML.

`resources/views/tickets/show.blade.php` line 3 renders it with Blade's raw-output directive:

```blade
<div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```

`{!! !!}` emits the string unescaped into the HTML document. Any HTML/JavaScript submitted as `description` (e.g. `<img src=x onerror=alert(document.cookie)>`) executes in the viewing user's browser.

## Fix

Use Blade's default escaping directive instead of the raw one, since the value is not actually sanitized HTML:

```blade
<article class="ticket">
  <h1>{{ $ticket['title'] }}</h1>
  <div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
</article>
```

`{{ }}` runs the value through `htmlspecialchars()` (ENT_QUOTES, UTF-8) before output, neutralizing `<`, `>`, `&`, and quotes so injected markup renders as inert text rather than executing.

If the product genuinely needs to let users submit a restricted subset of HTML (bold, links, etc.) for the description, escaping alone is too strict — instead sanitize server-side with a maintained allowlist-based HTML sanitizer (e.g. HTMLPurifier) in `TicketPresenter::present()` before the value is handed to the view, and keep the view using `{!! !!}` only on that sanitized output. Do not sanitize client-side and do not attempt to blocklist tags/attributes by hand.

Separately, rename the presenter key from `descriptionHtml` to something like `description` (plain) unless it is truly pre-sanitized HTML. The `Html` suffix currently signals "safe to render raw" to any future reader of the view, which is exactly the trap that produced this bug — a naming convention should only promise "raw-safe" for values that have actually passed through a sanitizer.

## Explanation

Blade's two output directives differ only in escaping: `{{ $var }}` HTML-encodes the value; `{!! $var !!}` prints it verbatim and is meant only for strings the developer has already vetted or sanitized as HTML (e.g. output of a Markdown renderer or HTML purifier). Here, `descriptionHtml` never passes through any such step — it is the raw request field renamed to look pre-sanitized, so the raw-output directive at line 3 is the sink that turns ordinary attacker-supplied text into executing markup. Switching to the escaping directive closes the immediate hole; the key rename prevents the same mistake from recurring the next time someone extends this view or reuses the presenter output elsewhere assuming "Html" already means safe.
