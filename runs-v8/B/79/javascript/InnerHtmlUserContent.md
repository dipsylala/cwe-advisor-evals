## Verdict

Exploitable

## Source

Untrusted data: `message.author` and `message.body` from `JSON.parse(event.data)` in the EventSource message handler. These come directly from remote user input forwarded by the server without modification, as stated in the code comment.

## Fix

**Vulnerable Code:**
```javascript
entry.innerHTML = `<span class="chat-author">${message.author}</span>: ${message.body}`;
```

**Fixed Code:**
```javascript
const span = document.createElement('span');
span.className = 'chat-author';
span.textContent = message.author;

entry.appendChild(span);
entry.appendChild(document.createTextNode(': '));
entry.appendChild(document.createTextNode(message.body));
```

## Explanation

The original code uses `innerHTML` with unescaped template literals containing untrusted user input, allowing XSS injection. The fix replaces `innerHTML` with DOM element creation and `textContent`/`createTextNode`, which automatically treats the input as text data rather than executable markup. This preserves the exact visual structure (a styled span followed by text) while preventing any injected HTML or JavaScript from executing. The `textContent` property and `createTextNode()` method always escape special characters, making them safe sinks for untrusted data.

## Behaviour changes

None. The DOM structure and visual output remain identical: a span element with class `chat-author` containing the author name, followed by a colon and the message body. All three are now rendered as text content rather than parsed HTML.
