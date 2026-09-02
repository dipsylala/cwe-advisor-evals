## Verdict

Confirmed. `appendChatMessage` builds an HTML string with unescaped, attacker-influenced chat content and assigns it via `innerHTML`, allowing stored/reflected script injection into the support widget's DOM.

## Source

`message.author` and `message.body`, received in `connectChatStream`'s `EventSource` `onmessage` handler (line 19, `JSON.parse(event.data)`) and passed unmodified into `appendChatMessage`. Per the inline comment, these values originate from the other chat participant's input and are forwarded by the server without modification - they are fully attacker-controlled.

## Fix

```javascript
function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;

  entry.appendChild(authorSpan);
  entry.appendChild(document.createTextNode(': ' + message.body));

  feed.appendChild(entry);
}
```

## Explanation

The original code interpolated `message.author` and `message.body` directly into an HTML template string and assigned it to `entry.innerHTML`. Because `innerHTML` parses its argument as markup, any HTML/JavaScript in either field (e.g. `<img src=x onerror=alert(1)>` as a message body) is parsed and executed in the victim's browser as soon as the chat message is rendered - a classic DOM-based/stored XSS delivered over the live-chat channel.

The fix removes the HTML-parsing sink entirely. `document.createElement('span')` builds the author element structurally instead of via a markup string, and `textContent` assigns the author value as literal text - the browser never interprets it as markup, no matter what characters it contains. The message body is likewise appended as a plain text node via `document.createTextNode`, preserving the original `"Author: body"` layout without ever passing attacker-controlled data through an HTML parser. The `chat-entry` and `chat-author` CSS classes are preserved so existing styling continues to apply.

This approach needs no sanitization library or allowlist: it is safe by construction because `textContent`/`createTextNode` never interpret their input as HTML, eliminating the injection vector rather than trying to filter it.
