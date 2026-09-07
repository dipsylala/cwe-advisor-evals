## Verdict
Confirmed real vulnerability. The code uses `innerHTML` to inject user-controlled chat message content (`message.author` and `message.body`) that comes directly from the other chat participant unmodified. An attacker can craft a message containing script tags or event handlers to execute arbitrary JavaScript in the victim's browser.

## Source
File: `InnerHtmlUserContent.js`, line 10
```javascript
entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;
```

The data flows from `event.data` (EventSource message, line 19) parsed as JSON, then passed to `appendChatMessage()` without sanitization. Both `message.author` and `message.body` are user-supplied and untrusted.

## Fix

### File: InnerHtmlUserContent.js

```javascript
// Renders incoming live-chat messages into the support widget panel.

function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // Create the author span safely using textContent
  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;
  entry.appendChild(authorSpan);

  // Add the separator and message body as text nodes
  entry.appendChild(document.createTextNode(': '));
  entry.appendChild(document.createTextNode(message.body));

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
The fix replaces the dangerous `innerHTML` assignment with DOM methods that automatically escape content: `textContent` and `createTextNode()`. This approach:

1. Preserves the original HTML structure (the `<span class="chat-author">` styling is retained)
2. Treats all user input as text, not markup—any angle brackets, quotes, or script tags in `message.author` or `message.body` are rendered literally as text, not interpreted as HTML or script
3. Avoids the need for manual escaping functions by using the browser's built-in text-safe APIs

An attacker's message like `<img src=x onerror=alert('XSS')>` will now render as literal text instead of executing code.
