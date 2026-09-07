## Verdict

VULNERABLE - CWE-79 (Cross-site Scripting) confirmed at line 29.

## Source

Untrusted data flows from `$_GET['agent_note']` (line 7) directly into a JavaScript string literal without any encoding. An attacker can inject arbitrary JavaScript by providing a payload that breaks out of the single-quoted string context.

**Data flow:**
1. User input source: `$agentNote = $_GET['agent_note'] ?? '';` (line 7)
2. Sink: `var agentNote = '<?php echo $agentNote; ?>';` (line 29)

Example attack: A query parameter like `?agent_note='; alert(1); //` would execute JavaScript in the victim's browser.

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
        // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
        var agentNote = <?php echo json_encode($agentNote, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
    </script>
</body>
</html>
```

## Explanation

The vulnerable code echoed untrusted user input directly into a JavaScript string literal without any encoding. An attacker could inject a single quote followed by JavaScript code to break out of the string and execute arbitrary script.

The fix replaces the unsafe `echo $agentNote;` with `json_encode($agentNote, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT)`. This function:

1. **Properly escapes the value**: All special characters including single quotes, double quotes, angle brackets, and ampersands are either escaped or encoded as Unicode escape sequences
2. **Produces a valid JSON string literal**: The output is a properly quoted JSON string that the JavaScript parser cannot be tricked out of
3. **Removes manual quote management**: The single quotes around the `echo` statement are removed since `json_encode()` provides its own quotes

For example, a malicious input like `test'; alert(1); //` becomes the JSON string `"test'; alert(1); //"`, which JavaScript safely interprets as a string value with no opportunity for breakout. The `'` escape sequence represents the single quote and is processed as a character within the string, not as a delimiter.

The `JSON_HEX_*` flags ensure that tag delimiters (`<`, `>`), ampersands, and quotes are all encoded in a way that prevents them from being interpreted as code in the JavaScript context.

## Behaviour changes

- **String representation**: The variable `agentNote` now contains the exact same string value it did before, so the behavior of the `innerText` assignment on line 30 remains unchanged—it still displays the agent note correctly in the banner.
- **Attack surface eliminated**: Payloads that attempt to break out of a string literal (e.g., `'; alert(1); //`) are now safely encoded and rendered harmless.
- **No functional regression**: Legitimate agent notes containing special characters like `"`, `<`, `>`, `&`, or `'` are properly displayed without alteration to the user-facing text.
- **Encoding visible in HTML source**: The JSON encoding is applied at render time in the PHP, so if an attacker views the page source, they will see the encoded form (e.g., `'`), not the raw input—this is the correct behavior for a JavaScript context escape.
