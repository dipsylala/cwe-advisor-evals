## Verdict

Confirmed. `entry.innerHTML` is assigned a template literal built from `message.author` and `message.body`, both of which come from the remote chat participant's input (forwarded unmodified by the server over the `EventSource` stream and parsed with `JSON.parse`). Neither value is encoded or sanitized before reaching the `innerHTML` sink, so a chat participant can inject `<img src=x onerror=...>`, `<svg onload=...>`, or similar markup into `author` or `body` and have it execute in every other participant's browser.

## Source

- `document.getElementById('startChatBtn').addEventListener('click', ...)` reads `sessionId` from a page input and calls `connectChatStream(sessionId)`.
- `connectChatStream` opens `new EventSource('/support/stream?session=' + sessionId)` and, on each `message` event, does `const message = JSON.parse(event.data)` - the code comment confirms `message.author` and `message.body` are "the other participant's chat input, forwarded by the server unmodified."
- `appendChatMessage(message)` is called with that untrusted object.
- Sink: line 10, `entry.innerHTML = \`<span class="chat-author">${message.author}</span>: ${message.body}\`;` - both `message.author` and `message.body` are interpolated directly into an HTML string assigned to `innerHTML`.

No validation, encoding, or sanitization occurs anywhere between the `EventSource` message and the `innerHTML` assignment.

## Fix

### File: InnerHtmlUserContent.js
```javascript
// Renders incoming live-chat messages into the support widget panel.

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

function connectChatStream(sessionId) {
  const source = new EventSource(`/support/stream?session=${sessionId}`);

  source.onmessage = (event) => {
    const message = JSON.parse(event.data);
    // message.author and message.body come straight from the other
    // participant's chat input, forwarded by the server unmodified.
    appendChatMessage(message);
  };

  return source;
}

document.getElementById('startChatBtn').addEventListener('click', () => {
  const sessionId = document.getElementById('sessionInput').value;
  connectChatStream(sessionId);
});
```

## Explanation

Chat author and body are plain display text, not rich HTML the widget needs to render as markup, so the applicable knowledge-base guidance is "replace `innerHTML` with `textContent`" rather than the DOMPurify path reserved for content that legitimately needs HTML formatting. The fix removes the `innerHTML` assignment entirely and rebuilds the same DOM structure (`div.chat-entry` containing `span.chat-author` followed by `": " + body`) using `document.createElement`, `textContent`, and `document.createTextNode`. `textContent` and `createTextNode` insert their argument as literal text - the browser never parses it as markup, so `<`, `>`, `&`, and quotes in a message render as visible characters instead of being interpreted as tags or attributes, closing the injection regardless of payload casing, encoding, or tag choice (e.g. `<svg onload=...>`). The visual output is unchanged: the rendered text is identical to what the original template literal produced for non-malicious input.

## Behaviour changes

- The `chat-entry` div's actual DOM composition changes from a single HTML-parsed subtree (one `innerHTML` write producing a `span` plus a trailing text node) to the same structure built with explicit DOM nodes (`createElement('span')` + two `appendChild` calls). The rendered text and visual layout are identical for legitimate input; only markup-like characters in `message.author` or `message.body` now render as literal text instead of being parsed as HTML, which is the intended fix.
- If other code queries `#chatFeed` and depends on `innerHTML` parsing entities (e.g. an author name containing `&amp;` intended to render as `&`), that no longer happens - entities are not interpreted by `textContent`/`createTextNode`, so such values render as the literal entity text. This matches the sink's now-corrected contract: chat input is untrusted text, not trusted markup.
- No library changes required; no new imports; only standard DOM APIs already implicitly available in this browser-side file.
- Verification: `node --check` was run against the fixed file in a scratch copy (outside the case directory) and reported no syntax errors. `document.createElement`, `document.createTextNode`, `Node.appendChild`, `Element.className`, and `Node.textContent` are all standard DOM APIs already used elsewhere in this same file (`document.createElement('div')`, `entry.className`), so no unverified names were introduced.
