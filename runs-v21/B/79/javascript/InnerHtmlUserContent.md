## Verdict

The finding is valid. Line 10 uses `innerHTML` with a template literal containing untrusted data (`message.author` and `message.body`) from a chat stream forwarded unmodified by the server. This is a direct XSS vulnerability; an attacker controlling chat input can inject malicious HTML/JavaScript that executes in victims' browsers.

## Source

Data flow:
1. EventSource stream receives messages from `/support/stream?session=${sessionId}`
2. Line 19: `JSON.parse(event.data)` deserializes the message
3. Line 20-21: Comment confirms `message.author` and `message.body` are "forwarded by the server unmodified"
4. Line 22: `appendChatMessage(message)` passes the message object
5. Line 10: `entry.innerHTML = <template literal>` - the sink

The untrusted values `message.author` and `message.body` reach `innerHTML` without any encoding or sanitization.

## Fix

### File: InnerHtmlUserContent.js

```javascript
// Renders incoming live-chat messages into the support widget panel.

function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // Build DOM elements instead of using innerHTML to prevent XSS
  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;

  entry.appendChild(authorSpan);
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

The fix replaces `innerHTML` with DOM element construction and `textContent` assignments. `textContent` does not parse HTML—it treats all input as plain text, preventing injection of script tags, event handlers, or other HTML-based payloads. Each untrusted value is assigned to `textContent`, which escapes it automatically as literal text.

The layout is preserved: a span element with class "chat-author" contains the author name, followed by a text node with ": ", followed by a text node with the message body. The visual output remains identical for legitimate content, but any special characters (< > & " ') are rendered literally instead of being interpreted as HTML markup.

## Behaviour changes

- Untrusted input is now treated as text, not markup: `<img onerror=alert(1)>` renders as literal text instead of executing
- HTML entities in input (e.g. `&lt;`) render as literal text rather than being decoded to `<`
- No change to legitimate use cases: author names and message text containing special characters now display correctly without accidental HTML interpretation
- No change to performance or DOM structure: same visual result, safer rendering method
