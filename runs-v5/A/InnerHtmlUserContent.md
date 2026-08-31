## Verdict

Confirmed. `entry.innerHTML` is assigned a template string built directly from `message.author` and `message.body`, both of which arrive unmodified from the remote chat participant via the server-sent event stream. Neither value is escaped before being placed in HTML, so a participant can inject markup (e.g. an `author` or `body` value containing `<img src=x onerror=...>` or `<script>`) that executes in the support agent's browser when the message is rendered.

## Source

- `message.author` and `message.body`, parsed from `event.data` in `connectChatStream`'s `source.onmessage` handler (`JSON.parse(event.data)`), sourced from `/support/stream?session=...`, an `EventSource` fed by the other chat participant's raw input.
- These flow unmodified into `appendChatMessage(message)`, which is the function containing the sink.

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

The original code used `innerHTML` with a template literal, so any HTML metacharacters in `message.author` or `message.body` were parsed as markup rather than displayed as text. Because both fields are attacker-controllable (they come from the other end of the chat, not from the local user), this is a stored/reflected DOM XSS: a malicious chat participant can inject script or event-handler attributes that run in the context of whoever is viewing the support widget.

The fix replaces the HTML-string assembly with DOM APIs that treat the values as data, not markup:

- `document.createElement('span')` plus `.textContent = message.author` builds the author label without parsing its contents as HTML.
- `document.createTextNode(': ' + message.body)` appends the message body as a plain text node, so any `<`, `>`, `&`, or quote characters in it are rendered literally instead of being interpreted as tags or attributes.

This preserves the original visual structure (`<span class="chat-author">author</span>: body`) while eliminating the injection point. No sanitization library is needed here since the content is never intended to contain real markup — using `textContent`/`createTextNode` is the safe-by-construction replacement for `innerHTML` when the inserted values are plain text. If the widget later needs to support rich formatting in messages, that would require a dedicated HTML sanitizer (e.g. DOMPurify) applied to the formatted subset before any `innerHTML` assignment, rather than reintroducing raw string interpolation.
