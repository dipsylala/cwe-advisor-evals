## Verdict

- **cwe_id**: CWE-79 (Improper Neutralization of Input During Web Page Generation / Cross-Site Scripting)
- **location**: `InnerHtmlUserContent.js`, line 10 (`entry.innerHTML = ...`)
- **verdict**: exploitable
- **confidence**: high

## Source

`connectChatStream` opens an `EventSource` on `/support/stream?session=...` and parses each server-sent event's `data` as JSON (`JSON.parse(event.data)`). The resulting `message.author` and `message.body` fields are, per the inline comment, forwarded unmodified by the server from the other chat participant's input - i.e. attacker-controlled text from the remote end of the chat. No validation, encoding, or sanitization is applied anywhere between `onmessage` and `appendChatMessage`.

## Fix

Vulnerable code:

```js
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // SINK: untrusted message.author / message.body interpolated into HTML and assigned via innerHTML
  entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;

  feed.appendChild(entry);
}
```

Fixed code:

```js
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

No third-party library recommendation applies here: `message.author` and `message.body` are plain chat text, not content that needs to render as HTML, so the JavaScript guidance's `textContent`/DOM-construction pattern is the correct primary defence rather than a sanitizer such as DOMPurify (which is for cases where some HTML must legitimately survive).

## Explanation

The original code built markup with a template literal and assigned it through `innerHTML`, so any HTML or `<script>`/event-handler markup present in `message.author` or `message.body` would be parsed and executed by the browser as part of the page - a classic DOM-based stored/reflected XSS via a taint sink named explicitly in the knowledge base (`innerHTML` built from a template literal). The fix removes the `innerHTML` sink entirely and rebuilds the same visual structure - a `span.chat-author` holding the author name, followed by `": "` and the message body - using `document.createElement` plus `textContent`/`createTextNode`. Both APIs insert their argument as literal text, never as parsed markup, so injected HTML or script in either field is displayed as plain characters instead of being interpreted, eliminating the weakness at the sink.

## Behaviour changes

- Final DOM shape is unchanged: `feed` still receives one appended `div.chat-entry` containing a `span.chat-author` (author text) followed by `": "` and the message body, matching the original template literal's layout.
- The only observable difference is that characters such as `<`, `>`, `&`, and quotes in `message.author` or `message.body` now render as literal text instead of being parsed as HTML/script - this is the intended effect of the fix, not an unrelated behavior change.
- No arguments, defaults, or return values were altered; `appendChatMessage` still returns `undefined` and still mutates `feed` as its only observable effect.
