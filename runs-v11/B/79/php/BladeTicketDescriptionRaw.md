# CWE-79 Remediation Report

## Verdict

Exploitable. Untrusted user input from `$request['description']` flows through the controller and presenter into the Blade template where it is rendered with `{!! !!}` (raw output), bypassing auto-escaping. An attacker can inject malicious JavaScript that executes in victims' browsers.

## Source

**Primary source:** User-supplied `$request['description']` in `TicketController.php` line 11

**Data flow path:**
1. `TicketController.show()` receives untrusted `$request['description']` (line 11)
2. Passes to `TicketPresenter.present()` as `$ticket['description']` (line 14)
3. Presenter re-exposes it as `'descriptionHtml'` without sanitization (TicketPresenter.php line 9)
4. Template renders it with `{!! !!}` which bypasses Blade's auto-escaping (show.blade.php line 3)

The variable name `descriptionHtml` is misleading; the data is untrusted user input, not sanitized HTML.

## Fix

**Vulnerable code (show.blade.php line 3):**
```
  <div class="ticket-description">{!! $ticket['descriptionHtml'] !!}</div>
```

**Fixed code:**
```
  <div class="ticket-description">{{ $ticket['descriptionHtml'] }}</div>
```

## Explanation

Replace Blade's raw output syntax `{!! !!}` with the auto-escaping syntax `{{ }}`. This enables Laravel Blade's built-in HTML entity encoding, which uses `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` flags. The fix converts untrusted user input into safe output by encoding special characters (`<`, `>`, `"`, `'`, `&`) as HTML entities, preventing script injection. The variable still displays correctly; legitimate content containing these characters is entity-encoded for safe rendering.

## Behaviour changes

None. The `{{ }}` operator provides the same output as `{!! !!}` except with HTML entity encoding applied. User-visible text content is unchanged; only the way special characters are transmitted to the browser changes from code to data.
