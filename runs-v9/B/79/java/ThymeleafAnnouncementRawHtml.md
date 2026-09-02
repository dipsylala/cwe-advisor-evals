## Verdict

Exploitable. CWE-79 (Cross-Site Scripting), confidence: high.

## Source

`AnnouncementController.preview(String draftId, Model model)` calls `service.loadDraft(draftId)` and puts the returned `AnnouncementDraft` on the model as `announcement` (`AnnouncementController.java`, line 16). `AnnouncementDraft.bodyHtml` (`AnnouncementService.java`, line 9) is the field that ultimately reaches the sink. In this fixture `AnnouncementService.loadDraft()` returns a hard-coded `AnnouncementDraft`, so the literal value in the file is fixed. The field is still treated as untrusted: it is named and typed as stored HTML content associated with an id supplied via `@RequestParam`, i.e. a draft that a real implementation would load from persistent storage (a value some author previously submitted), not content the server itself generates. Nothing between the load and the render performs any validation or encoding.

## Fix

Sink: `templates/announcement-preview.html`, line 5 — `th:utext="${announcement.bodyHtml}"`. `th:utext` is Thymeleaf's explicit auto-escaping bypass: it writes the string into the response verbatim, so any `<script>`, `<img onerror=...>`, or similar markup stored in `bodyHtml` executes in the viewer's browser. `th:text` on the adjacent `title` field (line 4) is already correct — it auto-escapes.

Vulnerable:
```html
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

Fixed:
```html
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

No library change is required. Thymeleaf's `th:text` already HTML-entity-encodes its output by default, so switching the attribute is sufficient to close this sink.

## Explanation

`th:utext` disables Thymeleaf's default output escaping for this element, so `announcement.bodyHtml` is written into the page unescaped; any HTML or script markup an author placed in the draft body renders and executes as part of the page rather than as inert text. Replacing `th:utext` with `th:text` restores Thymeleaf's default HTML-entity encoding for the same expression, so `<`, `>`, `&`, and quotes in the value are escaped before being written to the response, and any injected markup is displayed as literal text instead of being parsed by the browser.

## Behaviour changes

The announcement body will no longer render as HTML: any markup an author included for formatting (the `<p>` tags in the current sample data, or bold/italics/line breaks in real drafts) will now display as visible escaped text (e.g. `<p>Draft body</p>` shown literally) instead of being rendered as formatted HTML. If rendering author-authored rich text is an intended product feature rather than an oversight, this fix trades that formatting away for safety; restoring it would require running `bodyHtml` through an allowlist-based HTML sanitizer before the template renders it, keeping `th:utext` only on the sanitized result — a change the loaded guidance does not prescribe here, since it states the fix for `th:utext` is removing it in favor of `th:text`. No other arguments, return values, or control flow are changed.
