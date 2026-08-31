## Verdict

Exploitable. Untrusted chat message data (`message.author` and `message.body`) are interpolated directly into a template literal and set as `innerHTML` without any encoding at line 10, allowing XSS payload injection.

## Source

`message.author` and `message.body` originate from `JSON.parse(event.data)` received via `EventSource` at line 19. The code comment confirms these values are "forwarded by the server unmodified" from the other chat participant's input, making them untrusted, attacker-controlled data.

## Fix

**Vulnerable code:**
```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
  entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;

  feed.appendChild(entry);
}
```

**Fixed code:**
```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  // Create author span with safe text content
  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;

  // Create text node for colon separator
  const colonNode = document.createTextNode(': ');

  // Create text node for message body
  const bodyNode = document.createTextNode(message.body);

  entry.appendChild(authorSpan);
  entry.appendChild(colonNode);
  entry.appendChild(bodyNode);

  feed.appendChild(entry);
}
```

## Explanation

The vulnerable code interpolates untrusted `message.author` and `message.body` directly into a template literal that is set as `innerHTML`, causing the browser to parse and execute any HTML or script tags embedded in the data. An attacker can inject payloads like `<img src=x onerror=alert(1)>` or `<script>alert('xss')</script>` that execute in victims' browsers. The fix replaces `innerHTML` with DOM methods: creating elements and text nodes that explicitly use `textContent` to treat the untrusted data as text content rather than HTML markup. This prevents HTML/script parsing while preserving the visual structure (author name in a styled span, followed by the message body).

## Behaviour changes

None. The DOM structure and visual rendering are identical to the original code. The span element still receives the `chat-author` class for styling, the author name and body text still display in the same order with the colon separator, and `appendChild()` maintains the same DOM insertion contract.
