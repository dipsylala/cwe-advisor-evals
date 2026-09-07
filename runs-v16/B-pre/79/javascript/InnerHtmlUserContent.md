## Verdict

Exploitable. The `message.author` and `message.body` parameters are received from an external EventSource stream with no server-side sanitization (as documented in the code comment: "forwarded by the server unmodified"). They are interpolated directly into an HTML string and rendered via `innerHTML` at line 10, allowing arbitrary script injection.

## Source

`message.author` and `message.body` from `event.data` in the EventSource `onmessage` handler (line 19). The data originates from untrusted remote input (other participant's chat, forwarded unmodified by server).

## Fix

**Vulnerable code:**
```javascript
entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;
```

**Fixed code:**
```javascript
const authorSpan = document.createElement('span');
authorSpan.className = 'chat-author';
authorSpan.textContent = message.author;
entry.appendChild(authorSpan);

const textNode = document.createTextNode(': ' + message.body);
entry.appendChild(textNode);
```

## Explanation

The fix eliminates the `innerHTML` sink entirely by replacing it with DOM methods that treat input only as text data, never as executable HTML or script. `textContent` sets the span's content safely as plain text, and `createTextNode()` creates a text node for the message body. Since the HTML structure (the span wrapper with the `chat-author` class) is built programmatically rather than via string interpolation, untrusted data cannot break out of the text context and inject tags or event handlers. This satisfies the primary defence principle: use framework-safe rendering or DOM APIs instead of `innerHTML` with untrusted input.

## Behaviour changes

None. The fix preserves the original rendering contract: a span element with class `chat-author` containing the sender's name, followed by a colon and the message body, all appended to the feed. Text containing `<`, `>`, `&`, quotes, or other special characters now renders literally (e.g., `<script>alert('xss')</script>` appears as plain text in the message), which is the correct and expected behaviour for a chat widget.
