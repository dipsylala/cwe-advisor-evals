## Verdict

Confirmed: CWE-79 XSS on line 10 via `innerHTML` with untrusted user input.

## Source

`message.author` and `message.body` (line 10) originate from an untrusted EventSource stream. Comments on lines 20-21 confirm these fields come directly from the other participant's chat input, forwarded by the server unmodified.

## Fix

Replace the `innerHTML` assignment with DOM methods that treat input as plain text:

```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;
  
  entry.appendChild(authorSpan);
  entry.appendChild(document.createTextNode(': '));
  entry.appendChild(document.createTextNode(message.body));

  feed.appendChild(entry);
}
```

## Explanation

The vulnerability lies on line 10, where `innerHTML` is assigned a template literal containing untrusted `message.author` and `message.body` values. This causes the browser to parse the input as HTML/JavaScript, allowing attackers to inject malicious scripts (e.g., `<img onerror=...>`, `<svg onload=...>`) that execute in the victim's context.

The fix replaces `innerHTML` with safe DOM construction methods:
- `textContent` treats input as plain text and automatically escapes HTML characters
- `createTextNode()` creates text nodes that cannot contain executable markup
- The HTML structure (the `<span>` with class) is preserved by explicitly creating and classifying the DOM nodes

This pattern follows the CWE-79 JavaScript guidance: "Replace `innerHTML` with `textContent` or framework-safe rendering." The attacker's input is now data only, not code.

## Behaviour changes

- Any HTML special characters in `message.author` or `message.body` (e.g., `<`, `>`, `&`, `"`) are rendered as literal text instead of HTML markup
- Chat messages containing these characters now display correctly (e.g., `5 < 10` displays as written, not as truncated HTML)
- Injected scripts, event handlers, and tags are rendered as visible text rather than executed
- Visual output remains identical for legitimate content; only malicious content is neutralized
