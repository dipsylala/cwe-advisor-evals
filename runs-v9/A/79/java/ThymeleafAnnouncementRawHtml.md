## Verdict

Confirmed. `announcement-preview.html` renders `announcement.bodyHtml` with Thymeleaf's `th:utext`, which outputs the value verbatim with no HTML escaping. Any caller who can influence the draft's `bodyHtml` (directly, or indirectly through whatever backing store `AnnouncementService.loadDraft` will read from once it is no longer a stub) can inject arbitrary markup, including `<script>` tags or event-handler attributes, and have it execute in the browser of anyone who opens the preview link.

## Source

- Request entry point: `AnnouncementController.preview(@RequestParam String draftId, Model model)` in `AnnouncementController.java` takes the caller-supplied `draftId` and calls `service.loadDraft(draftId)`.
- `AnnouncementService.loadDraft(String draftId)` returns an `AnnouncementDraft(title, bodyHtml)`. In the current stub the body is a fixed literal, but the method signature and the field name (`bodyHtml`) make clear the intended data flow is "look up the draft's stored HTML body by id" - i.e. `bodyHtml` is expected to hold announcement content authored elsewhere (a CMS field, an admin/editor form, an imported feed, etc.), not a value the template itself is allowed to assume is safe.
- The draft is placed on the model as `announcement` and rendered in `templates/announcement-preview.html`.
- Sink: line 5, `<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>`. `th:utext` explicitly means "unescaped text" in Thymeleaf - it disables the engine's default HTML escaping and writes the string straight into the response body, in contrast to `th:text`, which HTML-escapes its value.

## Fix

Stop emitting `bodyHtml` as raw markup. Two changes, pick based on whether announcements are meant to carry any formatting:

- If the announcement body is plain text (most likely, given the stub content is a hardcoded string), change the sink to escape it:
  `<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>`
  `th:text` HTML-escapes the value, so any `<`, `>`, `&`, and quote characters render as literal text instead of being parsed as markup.

- If announcements are genuinely meant to support a limited set of HTML formatting (e.g. `<p>`, `<b>`, `<a>`), do not pass the raw stored value straight to `th:utext`. Sanitize it server-side, in `AnnouncementService` (or wherever the eventual real data source populates `bodyHtml`), with a dedicated HTML sanitizer such as the OWASP Java HTML Sanitizer (`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`). Build an explicit allowlist `PolicyFactory` (permit only the specific tags/attributes announcements need, e.g. `Sanitizers.FORMATTING.and(Sanitizers.LINKS)`), run every `bodyHtml` value through `policy.sanitize(rawHtml)` before it is stored or returned, and only then is it safe to keep rendering the sanitized result with `th:utext`. Do not sanitize by stripping specific tags yourself (e.g. regex removal of `<script>`) - a maintained allowlist sanitizer handles attribute-based vectors (`onerror=`, `javascript:` hrefs, etc.) that ad hoc stripping misses.

Either way, treat `draftId` as attacker-influenced input that determines which stored content gets rendered; the fix belongs at the point where that stored content is turned into markup, not at the parameter itself.

## Explanation

Thymeleaf escapes by default specifically so that model data - which routinely originates from user input, an editable data store, or an external feed - cannot be interpreted as HTML/JS by the browser. `th:utext` is an opt-out of that protection, meant for values a developer has already verified are safe HTML (e.g. output of a template fragment the application itself authored), not for content whose provenance traces back to an id supplied on the query string. Here the template trusts `announcement.bodyHtml` unconditionally, so once `loadDraft` is backed by real, editable announcement data, any HTML/JavaScript stored in that field is delivered verbatim to every viewer of `/announcements/preview?draftId=...`, giving a stored or reflected XSS depending on how drafts are populated. Switching the sink to `th:text` (or sanitizing before any `th:utext` use) removes the unescaped code path entirely rather than trying to filter dangerous input at the edge, which is the more reliable defense because it does not depend on anticipating every injection vector.
