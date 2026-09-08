## Verdict

CONFIRMED. Line 10 uses `innerHTML` with unsanitized user-supplied values (`message.author` and `message.body`), enabling arbitrary JavaScript injection.

## Source

Line 10 in InnerHtmlUserContent.js:
```javascript
entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;
```

The `message` object originates from an EventSource stream (line 19), where `message.author` and `message.body` come from unmodified server data (line 20-21 comment) that ultimately derives from untrusted chat input.

## Fix

### File: InnerHtmlUserContent.js

```javascript
// Renders incoming live-chat messages into the support widget panel.

function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // Create author span and set text content safely
  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;
  entry.appendChild(authorSpan);

  // Add separator and body text safely
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

The remediation replaces the unsafe `innerHTML` assignment with safe DOM construction:

1. **Create structured elements explicitly**: The `<span class="chat-author">` wrapper is now built with `createElement` and `appendChild`, preserving the intended layout and styling without passing user data through HTML parsing.

2. **Use `textContent` for user data**: `message.author` is assigned to `authorSpan.textContent`, which treats the value as plain text only—any HTML or script tags become literal text strings, not executable code.

3. **Use `createTextNode` for composite text**: The separator (`: `) and body are safely combined via `createTextNode`, again preventing interpretation as HTML.

This approach closes the XSS vector while maintaining the original visual structure and behavior of the chat widget.
