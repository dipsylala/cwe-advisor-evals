## Verdict

Exploitable. CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting), confirmed. Confidence: high.

Location: `InnerHtmlUserContent.js`, line 10, inside `appendChatMessage(message)`.

## Source

`message.author` and `message.body` originate from `connectChatStream`'s `EventSource` handler (`source.onmessage`), which `JSON.parse`s the raw event payload from `/support/stream?session=...`. The inline comment states these fields "come straight from the other participant's chat input, forwarded by the server unmodified" - the server relays them without validation or encoding, so both fields are attacker-controlled by any chat participant, with no transformation between that network source and the render call.

That object is passed unmodified into `appendChatMessage`, which is the only place either field is used, and both values are interpolated directly into a template literal assigned to `entry.innerHTML` (line 10) - a taint sink that parses its input as HTML and executes any `<script>`-equivalent markup it contains (e.g. `<img src=x onerror=...>`). There is no encoding, sanitization, or allowlist check anywhere on this path, so the flow is exploitable as reported: any chat participant can inject `message.author` or `message.body` values containing HTML/JS that will execute in the support widget of every viewer of that feed.

Sink contract for `entry.innerHTML =`: it returns nothing (property setter); it discards and replaces any existing children of `entry` (not relevant here, since `entry` is freshly created); it takes no separate encoding/config argument - the entire string is parsed as HTML with no implicit safe default; and it does not throw on malformed markup, it just parses leniently.

## Fix

No third-party library is required - the guidance's primary defence for this case is to stop parsing the value as HTML at all. `message.author` and `message.body` are rendered as plain chat text, not rich/formatted HTML, so `textContent` is the correct primary defence (DOMPurify is for cases where the untrusted value legitimately needs to carry HTML markup, which is not the case here).

Vulnerable code:

```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // SAST FINDING: CWE-79 reported here. Sink is the next statement.
  entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;

  feed.appendChild(entry);
}
```

Fixed code:

```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;

  entry.appendChild(authorSpan);
  entry.appendChild(document.createTextNode(`: ${message.body}`));

  feed.appendChild(entry);
}
```

## Explanation

The fix removes the `innerHTML` sink entirely and rebuilds the same DOM structure - a `span.chat-author` holding the author name, followed by a text node holding `: ` plus the message body - using `createElement`/`textContent`/`createTextNode` instead of an HTML-parsing assignment. `textContent` and `createTextNode` insert their argument as literal character data; the browser never re-parses it as markup, so any `<`, `>`, `&`, or quote characters in `message.author` or `message.body` render as visible text instead of being interpreted as tags, attributes, or event handlers. This closes the injection at the sink itself (the only place either tainted field is used) rather than relying on validation upstream that the untrusted server-relayed payload cannot be trusted to have passed.

## Behaviour changes

- The `chat-author` span and the `chat-entry` div keep the same tag names, classes, and nesting, so existing CSS selectors continue to match and the visual layout is unchanged.
- Legitimate content containing HTML-significant characters (e.g. an author name like `A & B`, or message text containing `<3`) now renders as literal text instead of being interpreted as markup; previously such characters would have been silently swallowed or misrendered by the HTML parser, so this is a correctness improvement, not a regression.
- No change to `connectChatStream`, the `EventSource` handling, function signatures, or return values. Nothing the original code returned or relied on downstream is affected.
