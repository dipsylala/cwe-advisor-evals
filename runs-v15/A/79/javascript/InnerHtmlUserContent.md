## Verdict

Confirmed. Line 10 uses `innerHTML` with unsanitized user-controlled data (`message.author` and `message.body`) interpolated into an HTML template. Since these values come from the server unmodified (per the comment), an attacker can inject script tags or event handlers to achieve arbitrary code execution in the victim's browser.

## Source

```javascript
entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;
```

The `message.author` and `message.body` values are JSON-decoded from an EventSource stream connected to `/support/stream?session={sessionId}` and passed directly into the DOM via `innerHTML` without sanitization.

## Fix

Replace the `innerHTML` assignment with DOM methods that treat user content as text, not HTML:

```javascript
const authorSpan = document.createElement('span');
authorSpan.className = 'chat-author';
authorSpan.textContent = message.author;

entry.appendChild(authorSpan);
entry.appendChild(document.createTextNode(': ' + message.body));
```

## Explanation

`innerHTML` parses its argument as HTML and executes any script tags or event handler attributes. Using `textContent` (or `createTextNode`) instead ensures the content is treated as plain text and rendered literally, preventing XSS injection. This preserves the chat author styling via the span element while safely handling untrusted content.
