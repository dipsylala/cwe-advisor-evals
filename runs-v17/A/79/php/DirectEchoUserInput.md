## Verdict
CONFIRMED. The code at line 27 echoes user-supplied input from `$_POST['note']` directly into HTML content without escaping, enabling XSS injection.

## Source
`$_POST['note']` is user-controlled input that flows directly into the HTML output via `echo` on line 27, passing through no sanitization.

## Fix
### File: DirectEchoUserInput.php
```php
<?php
// ticket-status.php - support ticket lookup page

function findTicketById(string $id): array
{
    $tickets = [
        '1001' => ['status' => 'Open'],
        '1002' => ['status' => 'Closed'],
    ];
    return $tickets[$id] ?? ['status' => 'Unknown'];
}

$ticketId = $_GET['ticket_id'] ?? '';
$requesterName = $_GET['requester'] ?? 'Guest';
$ticket = findTicketById($ticketId);
?>
<!DOCTYPE html>
<html>
<head><title>Ticket Status</title></head>
<body>
<h1>Support Ticket Lookup</h1>
<p>Hello, <?php echo htmlspecialchars($requesterName, ENT_QUOTES, 'UTF-8'); ?></p>
<p>Ticket #<?php echo htmlspecialchars($ticketId, ENT_QUOTES, 'UTF-8'); ?> status: <?php echo htmlspecialchars($ticket['status'], ENT_QUOTES, 'UTF-8'); ?></p>

<?php
// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($_POST['note'] ?? '', ENT_QUOTES, 'UTF-8') . "</div>";
?>
</body>
</html>
```

## Explanation
The fix applies `htmlspecialchars()` with `ENT_QUOTES` flag and UTF-8 encoding to escape all user-supplied values before outputting them to HTML. This converts dangerous characters (`<`, `>`, `"`, `'`, `&`) into their HTML entity equivalents, preventing script injection. The fix also applies escaping to the other user inputs on lines 22 and 23 for defense-in-depth, and adds a null coalesce operator to `$_POST['note']` to prevent undefined index notices when the form field is not submitted.
