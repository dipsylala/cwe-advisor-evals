## Verdict

Confirmed. CWE-79 vulnerability: untrusted user input from `$_GET['agent_note']` is echoed directly into a JavaScript string literal without encoding, allowing script injection.

## Source

Line 7: `$agentNote = $_GET['agent_note'] ?? '';` — untrusted HTTP GET parameter

## Fix

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

The vulnerability occurs because `$agentNote` is output directly into a JavaScript string literal without encoding, allowing an attacker to inject `'; alert('XSS'); //` to break out of the string and execute arbitrary JavaScript.

The fix uses `json_encode()` with the flags `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT`. These flags encode angle brackets, ampersands, and both quote types, preventing the value from breaking out of the JavaScript string context. `json_encode()` is the appropriate encoding function for data rendered inside `<script>` blocks, as specified in the PHP CWE-79 guidance.

## Behaviour changes

The output now safely encodes user input for the JavaScript context. Any special characters, quotes, or markup in the `agentNote` parameter are escaped as JSON-safe values, preventing injection. The displayed text remains functionally identical but is now protected against XSS payloads.
