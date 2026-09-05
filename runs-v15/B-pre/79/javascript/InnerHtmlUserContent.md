## Verdict

exploitable

## Source

`message.author` and `message.body` from `JSON.parse(event.data)` at lines 19-22. Comments confirm these come "straight from the other participant's chat input, forwarded by the server unmodified."

## Fix

**Vulnerable code (line 10):**
```javascript
entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;
```

**Fixed code (replaces line 10):**
```javascript
const authorSpan = document.createElement('span');
authorSpan.className = 'chat-author';
authorSpan.textContent = message.author;
entry.appendChild(authorSpan);

const separator = document.createTextNode(': ');
entry.appendChild(separator);

const messageText = document.createTextNode(message.body);
entry.appendChild(messageText);
```

## Explanation

The fix replaces `innerHTML` with safe DOM construction methods (`createElement`, `textContent`, `createTextNode`, `appendChild`). These APIs treat all string values as data, not executable markup. The author name and message body are inserted into text nodes, preventing script injection. The styled span wrapper is preserved using `createElement` and class assignment, maintaining the original presentation while eliminating the XSS sink.

## Behaviour changes

The fix constructs the same visual output but through three appended children instead of parsing a template string as HTML:
- `<span class="chat-author">` is created and styled via `className`
- Author name text rendered via `textContent` instead of interpolation
- Separator `: ` inserted as a text node
- Message body inserted as a text node

No parameters are omitted or defaults altered. The appended elements maintain the visual hierarchy and styling of the original code while removing HTML parsing.
