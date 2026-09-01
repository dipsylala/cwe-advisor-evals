## Verdict
Confirmed vulnerability. User-controlled message data is directly interpolated into `innerHTML` without escaping, allowing arbitrary HTML/JavaScript injection.

## Source
`message.author` and `message.body` from JSON parsed server response. These originate from unvalidated user input (the other participant's chat message), forwarded by the server unmodified as noted in the code comment.

## Fix
Replace `innerHTML` assignment with safe DOM construction using `textContent` for text nodes:

```javascript
const authorSpan = document.createElement('span');
authorSpan.className = 'chat-author';
authorSpan.textContent = message.author;

entry.appendChild(authorSpan);
entry.appendChild(document.createTextNode(': '));
entry.appendChild(document.createTextNode(message.body));
```

Alternatively, use `textContent` for the entire assembled string if HTML structure is not needed:

```javascript
entry.textContent = `${message.author}: ${message.body}`;
```

Then add the class separately:
```javascript
entry.className = 'chat-entry';
```

## Explanation
`innerHTML` parses its argument as HTML/XML, so any injected script tags or event handlers in the message data execute in the page context. `textContent` treats the input as literal text and prevents script execution. Since author and body are user-generated chat content without legitimate HTML markup, they should never be parsed as markup. Using `textContent` or creating elements and setting their text via the DOM API ensures user input is always treated as content, not code.
