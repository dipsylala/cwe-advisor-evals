## Verdict
The vulnerability is **CONFIRMED**. Line 10 uses `innerHTML` to insert user-supplied content (`message.author` and `message.body`) directly into the DOM, creating a classic reflected XSS vector.

## Source
Lines 19-22: `message.author` and `message.body` originate from `event.data` received via EventSource, which is parsed from server response. The code comment explicitly states these values come "straight from the other participant's chat input, forwarded by the server unmodified."

## Fix
Replace the `innerHTML` assignment with safe DOM construction using `textContent`:

```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  const author = document.createElement('span');
  author.className = 'chat-author';
  author.textContent = message.author;
  
  entry.appendChild(author);
  entry.appendChild(document.createTextNode(': ' + message.body));

  feed.appendChild(entry);
}
```

## Explanation
The original code uses `innerHTML` to inject a template string containing unsanitized user input. An attacker can inject HTML and JavaScript—for example, `<img src=x onerror="alert('xss')">` in the message body—which will execute when the DOM renders.

The fix replaces `innerHTML` with explicit DOM construction and `textContent`. The `textContent` property treats its value as a string literal, automatically escaping any special characters and preventing script execution. The span's class is applied via the `className` property, and the message text is appended as a text node, ensuring the HTML structure is preserved without introducing injection points.
