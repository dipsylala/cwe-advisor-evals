## Verdict

Exploitable. Untrusted user input flows directly to an unescaped HTML output sink.

## Source

`@RequestParam("note") String submitterNote` at line 24 receives user-controlled input with no validation or constraints.

## Fix

Change line 26 from:
```java
String fragment = "<div class=\"ticket-note\" th:utext=\"${note}\">Preview</div>";
```

to:
```java
String fragment = "<div class=\"ticket-note\" th:text=\"${note}\">Preview</div>";
```

## Explanation

The vulnerability occurs because `th:utext` is Thymeleaf's unescaped-text directive—it renders the variable value directly into HTML without encoding special characters. This allows an attacker to inject `<script>` tags or event handlers. The fix replaces `th:utext` with `th:text`, which enables Thymeleaf's default HTML entity encoding. With `th:text`, characters like `<`, `>`, `&`, `'`, and `"` are automatically encoded to HTML entities (`&lt;`, `&gt;`, `&amp;`, `&#x27;`, `&quot;`), preventing script injection while preserving legitimate content that happens to contain those characters.

## Behaviour changes

Legitimate text containing `<`, `>`, `&`, or quotes now renders as escaped HTML entities rather than raw markup. For example, if a user enters "Hello & goodbye", it displays as "Hello &amp; goodbye" in the browser while the page itself is unaffected. Attackers can no longer inject HTML tags or JavaScript.
