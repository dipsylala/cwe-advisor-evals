## Verdict
exploitable

## Source
Line 7: `$agentNote = $_GET['agent_note'] ?? '';` — untrusted user input from query parameter is stored without validation.

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
        // Fixed: use json_encode with context-specific flags to safely encode for JavaScript string context
        var agentNote = <?php echo json_encode($agentNote, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
    </script>
</body>
</html>
```

## Explanation
The vulnerability on line 29 arose from embedding untrusted user input directly into a JavaScript string literal without escaping. An attacker could close the string and inject arbitrary JavaScript by providing input like `'; alert('xss'); //`. The fix applies `json_encode()` with context-specific flags (`JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT`) to properly escape the value for use inside a `<script>` block. This produces a valid JSON string literal that JavaScript can parse safely, preventing the attacker's quotes from breaking out of the string context. The result is already a complete quoted string, so the surrounding single quotes are removed.

## Behaviour changes
The `json_encode()` output produces a properly quoted JSON string (e.g., `"value"` instead of `'value'`), which JavaScript interprets identically as a string literal. Special characters and quotes within the user input are escaped using Unicode sequences and JSON escaping rules, making them safe for JavaScript parsing. The contract of `document.getElementById('banner').innerText` remains unchanged — it still receives the decoded string value.
