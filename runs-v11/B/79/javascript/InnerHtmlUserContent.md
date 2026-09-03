## Verdict
Exploitable

## Source
`message.author` and `message.body` from EventSource stream data, parsed from untrusted server response and passed directly to `appendChatMessage()` without validation or encoding.

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

entry.appendChild(document.createTextNode(': '));
entry.appendChild(document.createTextNode(message.body));
```

## Explanation
The vulnerability arises because `innerHTML` interprets its argument as HTML markup, so untrusted data containing `<script>`, event handlers, or other HTML constructs will be parsed and executed as code. Since `message.author` and `message.body` come from a remote server and are forwarded unmodified, an attacker can inject malicious scripts. The fix replaces `innerHTML` with safe DOM construction: `textContent` and `createTextNode()` treat their arguments as text only, never as markup, preventing any HTML parsing. The span element is still created and styled correctly via `createElement()` and `className`, preserving the original layout and appearance without the XSS risk.

## Behaviour changes
None. The replacement constructs the same DOM tree - a span with class `chat-author` containing the author name, followed by a text node with `: ` and another text node with the message body. `textContent` and `createTextNode()` render the output identically to `innerHTML` would, but safely treat all content as text rather than markup. The display, styling, and event handling remain unchanged.
