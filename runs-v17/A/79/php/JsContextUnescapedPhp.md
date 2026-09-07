## Verdict

The vulnerability is confirmed. Line 29 outputs unsanitized user input (`$agentNote` from `$_GET['agent_note']`) directly into a JavaScript string context, allowing XSS injection. An attacker can break out of the string and execute arbitrary JavaScript.

## Source

**File:** JsContextUnescapedPhp.php  
**Line:** 29  
**Vulnerable Code:**
```php
var agentNote = '<?php echo $agentNote; ?>';
```

The `$agentNote` variable originates from line 7 (`$_GET['agent_note']`) with no sanitization, and is output into a JavaScript string context without escaping.

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
        var agentNote = <?php echo json_encode($agentNote); ?>;
        document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
    </script>
</body>
</html>
```

## Explanation

The vulnerability stems from outputting user-controlled input directly into a JavaScript string context without escaping. The fix uses `json_encode()` to properly escape the value for JavaScript/JSON context.

**Why this works:**
- `json_encode()` wraps the value in quotes and escapes all special characters (backslashes, quotes, newlines, etc.)
- An attacker's input like `'); alert('XSS'); //` becomes the safely escaped string `"'); alert('XSS'); //"`
- The JavaScript parser treats the entire result as a string literal, preventing breakout and injection
- This is the safe pattern for outputting data into JavaScript contexts in PHP

**Example attacks prevented:**
- `'); alert('XSS'); //` → safely becomes `"'); alert('XSS'); //"`
- `\x3cscript>alert(1)\x3c/script>` → safely becomes `"\\x3cscript>alert(1)\\x3c/script>"`
