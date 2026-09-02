## Verdict

Exploitable. The sink at line 10 injects untrusted server data directly into the DOM via `innerHTML` using template literal interpolation with no escaping or sanitization.

## Source

Line 19: `const message = JSON.parse(event.data);` receives untrusted data from the server via EventSource. Fields `message.author` and `message.body` are extracted and flow to the sink without any validation or transformation.

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

The original code uses `innerHTML` with template literal interpolation to inject untrusted server data directly into the DOM. This allows an attacker who controls server responses to inject malicious HTML and JavaScript payloads that execute in the victim's browser. The fix replaces `innerHTML` with safe DOM construction methods: `createElement()` to create elements, `textContent` to set plain text content (which automatically escapes HTML metacharacters), and `createTextNode()` to inject text nodes. This ensures user-supplied data remains data and cannot be interpreted as HTML markup or executable code.

## Behaviour changes

None. The rendered output is visually identical: a span with class "chat-author" containing the author's name, followed by ": " and the message body. All three are rendered as plain text. The data flow into the DOM is identical in terms of the final document structure produced and the visible content.
