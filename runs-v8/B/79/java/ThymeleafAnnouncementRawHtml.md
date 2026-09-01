## Verdict

exploitable

## Source

The `announcement` object, which contains untrusted data returned from `AnnouncementService.loadDraft()`, is passed to the Thymeleaf template via `model.addAttribute("announcement", ...)` in `AnnouncementController.preview()`.

## Fix

**Vulnerable code:**
```
<section class="announcement-body" th:utext="${announcement.bodyHtml}"></section>
```

**Fixed code:**
```
<section class="announcement-body" th:text="${announcement.bodyHtml}"></section>
```

## Explanation

The vulnerability is located at line 5 of `announcement-preview.html`. The `th:utext` directive explicitly disables Thymeleaf's automatic HTML entity encoding, rendering the untrusted `announcement.bodyHtml` value as raw HTML. This allows an attacker to inject arbitrary HTML and JavaScript that executes in the victim's browser. The fix replaces `th:utext` with `th:text`, which enables Thymeleaf's built-in HTML entity encoding by default. This encoding converts dangerous characters like `<`, `>`, `&`, and quotes into HTML entities, preventing script injection while preserving legitimate content rendering.

## Behaviour changes

none

