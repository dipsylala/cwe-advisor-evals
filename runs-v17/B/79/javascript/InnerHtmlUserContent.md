## Verdict

Confirmed: CWE-79 XSS via `innerHTML` with untrusted user-controlled data from chat messages.

## Source

`message.author` and `message.body` are received from a WebSocket EventSource endpoint (`/support/stream?session=${sessionId}`) and parsed via `JSON.parse(event.data)`. These values originate directly from the other chat participant's input, forwarded unmodified by the server, making them untrusted.

## Fix

Replace `innerHTML` with safe DOM construction using `textContent` to prevent HTML/script interpretation:

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

  entry.appendChild(document.createTextNode(': ' + message.body));

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

The original code used `innerHTML` to insert untrusted user data directly into the DOM, which causes the browser to parse and execute any HTML or JavaScript in the input. An attacker in the chat could inject `<img src=x onerror="alert('XSS')">` or similar payloads that would execute in other users' browsers.

The fix replaces this with safe DOM construction: `createElement()` and `textContent`. The span element and class names are created programmatically (untrusted), then text content is inserted using `textContent`, which treats all input as plain text and prevents HTML/script interpretation. The user data (author and body) can no longer be interpreted as code. The visual output and DOM structure remain identical—only the injection surface is removed.

All APIs used (`createElement`, `textContent`, `createTextNode`, `appendChild`, `className`) are standard DOM methods available in all modern browsers since at least IE9.

## Behaviour changes

- `message.author` and `message.body` values containing HTML special characters (`<`, `>`, `&`, `"`, `'`) will now render as literal text instead of being parsed as HTML. For example, if a user's name is "Alice & Co.", it will display exactly as written instead of attempting HTML interpretation.
- The visual rendering and styling via the `chat-entry` and `chat-author` classes remains unchanged.
- No external dependencies added; fix uses only native browser DOM APIs.
