## Verdict

Confirmed. `appendChatMessage` builds an HTML string with `message.author` and `message.body` interpolated directly into a template literal and assigns it to `entry.innerHTML`. Both fields originate from the other chat participant's input and are forwarded by the server unmodified, so an attacker-controlled chat message such as `<img src=x onerror=alert(document.cookie)>` is parsed and executed as markup in every other participant's browser (stored/reflected DOM XSS via the live-chat feed).

## Source

`connectChatStream` opens an `EventSource` on `/support/stream` and parses each server-sent event as JSON (`event.data` -> `message`). `message.author` and `message.body` are attacker-controlled (the other chat participant's raw input, relayed by the server without sanitization) and flow unmodified into `appendChatMessage(message)`, which is the sink at line 10.

## Fix

### File: InnerHtmlUserContent.js
```javascript
// Renders incoming live-chat messages into the support widget panel.

function appendChatMessage(message) {
  const feed = document.getElementById('chatFeed');

  const entry = document.createElement('div');
  entry.className = 'chat-entry';

  const authorSpan = document.createElement('span');
  authorSpan.className = 'chat-author';
  authorSpan.textContent = message.author;

  entry.appendChild(authorSpan);
  entry.appendChild(document.createTextNode(`: ${message.body}`));

  feed.appendChild(entry);
}

function connectChatStream(sessionId) {
  const source = new EventSource(`/support/stream?session=${sessionId}`);

  source.onmessage = (event) => {
    const message = JSON.parse(event.data);
    // message.author and message.body come straight from the other
    // participant's chat input, forwarded by the server unmodified.
    appendChatMessage(message);
  };

  return source;
}

document.getElementById('startChatBtn').addEventListener('click', () => {
  const sessionId = document.getElementById('sessionInput').value;
  connectChatStream(sessionId);
});
```

## Explanation

The original code concatenated untrusted `author` and `body` values into an HTML string and handed it to `innerHTML`, which parses the string as markup - any tag or event-handler attribute in either field executes in the viewing user's session. The fix removes the HTML-parsing sink entirely: the author is placed in its own `span.chat-author` via `textContent`, which the DOM treats as literal text with no markup interpretation, and the `: {body}` portion is appended as a plain text node with `document.createTextNode`, preserving the original visual layout (author span, colon, body) without ever invoking the HTML parser on user data. No allowlist or escaping library is needed because the untrusted values never re-enter an HTML-parsing context, and the rendered output is identical to the original design's intent for legitimate chat content (plain text messages), so no legitimate input is rejected or altered.
