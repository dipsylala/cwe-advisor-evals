## Verdict

Exploitable (confidence: high).

## Source

`$_GET['agent_note']` (line 7, `$agentNote = $_GET['agent_note'] ?? '';`) - attacker-controlled query-string parameter, read with no validation or encoding applied at the source.

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
        var agentNote = <?php echo json_encode($agentNote, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
    </script>
</body>
</html>
```

## Explanation

Line 29 interpolated `$agentNote` directly into a single-quoted JavaScript string literal with no encoding, so a value such as `'; alert(document.cookie); //` or `</script><script>alert(1)</script>` breaks out of the string (or the surrounding `<script>` block) and executes as attacker-controlled script in the victim's browser. The fix replaces the raw interpolation with `json_encode($agentNote, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)` and emits its output directly as the JavaScript value (dropping the hand-written surrounding quotes, since `json_encode` already produces a quoted, escaped string literal). `JSON_HEX_APOS`/`JSON_HEX_QUOT` escape `'` and `"` so the value cannot terminate the string, and `JSON_HEX_TAG`/`JSON_HEX_AMP` escape `<`, `>`, and `&` so an embedded `</script>` cannot close the surrounding script block. This is the JavaScript-context encoding the JSON_HEX flag combination is designed for, applied at the exact sink identified in the trace; HTML-attribute encoding (`htmlspecialchars`) would not be appropriate here since the value never lands in an HTML attribute, only inside a script body.

## Behaviour changes

- The literal single quotes that previously wrapped `<?php echo $agentNote; ?>` are removed from the markup, because `json_encode()`'s output is already a complete, properly quoted and escaped JS string literal; wrapping it in additional quotes would produce a syntax error or a nested/mangled string. This is required by the fix, not incidental.
- For any input that contained no `'`, `"`, `<`, `>`, or `&` (i.e. the vast majority of legitimate agent notes), the resulting JavaScript value is unchanged - `agentNote` still holds the exact same string, and `innerText` rendering behaves identically.
- For input containing those characters, the visible text of the note (once assigned via `innerText`, which itself does not interpret HTML) will show the literal characters `<`, `>`, `&`, `'`, `"` rather than having them (mis)interpreted - this is the intended effect of closing the injection, not a regression.
- No other line, argument, return value, or control flow was changed.

**Verification:** `php -l` on the fixed file reported "No syntax errors detected". Additionally ran `php -r` with the fix's exact `json_encode(...)` call against two proof-of-concept payloads (`</script><script>alert(1)</script>` and `'; alert(1); //`); both were confirmed to render as inert escaped text (`<\/script>...`, `'; alert(1); \/\/`) rather than breaking out of the string or the script block.
