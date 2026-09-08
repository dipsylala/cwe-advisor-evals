## Verdict
Confirmed. Line 27 directly echoes unsanitized `$_POST['note']` into HTML output without escaping, creating a stored XSS vulnerability. An attacker can inject malicious JavaScript that executes in the browser of any user viewing that note. Lines 22 and 23 also output unsanitized user input from `$_GET` parameters and should be fixed to prevent reflected XSS.

## Source
Line 27 (primary sink):
```php
echo "<div class='requester-note'>Note from requester: " . $_POST['note'] . "</div>";
```

Lines 22-23 (secondary sinks):
```php
<p>Hello, <?php echo $requesterName; ?></p>
<p>Ticket #<?php echo $ticketId; ?> status: <?php echo $ticket['status']; ?></p>
```

All three use unescaped output of user-controlled input into HTML context.

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
The fix applies `htmlspecialchars()` to every instance of user input echoed into HTML context, with `ENT_QUOTES` to escape both double and single quotes and `UTF-8` charset specification. This converts dangerous characters (`<`, `>`, `&`, `"`, `'`) into their HTML entities, preventing the browser from interpreting them as markup or script delimiters.

Line 27 is the critical sink: the `$_POST['note']` value is now escaped before output.

Lines 22-23 receive the same treatment to prevent reflected XSS through `$_GET['requester']` and `$_GET['ticket_id']`. Line 27 also adds a null-coalesce operator to handle missing POST data safely.

The function `htmlspecialchars()` is a built-in PHP function available in all versions and is the standard defense for context-appropriate escaping in HTML output.
