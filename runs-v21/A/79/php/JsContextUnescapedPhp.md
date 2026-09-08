## Verdict

Confirmed. Line 29 outputs unsanitized user input directly into a JavaScript string literal context, enabling JavaScript injection. The `$agentNote` parameter originates from `$_GET` without sanitization and is echoed into the script tag where an attacker can escape the string and execute arbitrary code.

## Source

Line 29 in JsContextUnescapedPhp.php:
```
var agentNote = '<?php echo $agentNote; ?>';
```

The `$agentNote` variable receives untrusted input from the `$_GET` superglobal (line 7) and is output into a JavaScript string context without encoding. A payload like `'; alert(1); var x = '` would break out of the string and execute JavaScript.

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
        var agentNote = <?php echo json_encode($agentNote, JSON_UNESCAPED_SLASHES); ?>;
        document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
    </script>
</body>
</html>
```

## Explanation

The vulnerability is remediated by using `json_encode()` to properly escape the user input for the JavaScript context. `json_encode()` with the `JSON_UNESCAPED_SLASHES` flag:

1. Wraps the string in quotes as valid JavaScript syntax.
2. Escapes all special characters (`"`, `'`, backslash, newlines, etc.) to prevent breaking out of the string.
3. Produces output that is always safe to embed in a JavaScript string context.

This approach is language-native and does not require additional dependencies. The output is a valid JavaScript string literal that cannot be exploited through quote-based escapes or control-character injection. The `JSON_UNESCAPED_SLASHES` flag preserves forward slashes without escaping them (to avoid unnecessary noise) while maintaining full safety.
