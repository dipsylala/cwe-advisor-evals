## Verdict
Confirmed. Reflected XSS: `$_POST['note']` is concatenated directly into an HTML response with no output encoding.

## Source
`$_POST['note']` (line 27), read directly in the HTML-generation context. `$_GET['ticket_id']` (line 13) and `$_GET['requester']` (line 14) are also user-controlled and reach `echo` unescaped at lines 22-23, so they carry the identical weakness.

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
$note = $_POST['note'] ?? '';
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($note, ENT_QUOTES, 'UTF-8') . "</div>";
?>
</body>
</html>
```

## Explanation
Every value echoed into the page - `$requesterName`, `$ticketId`, `$ticket['status']`, and the flagged `$_POST['note']` - originates from attacker-controlled request data (`$_GET`/`$_POST`) and was written into the HTML body with a raw `echo`, so any HTML or `<script>` content in those parameters executes in the victim's browser (reflected XSS). `$ticket['status']` is included because it falls back to the unvalidated `$id` lookup key when the ticket is not found, so it does not fully break the taint chain either.

The fix applies PHP's built-in `htmlspecialchars()` at the point of output (the sink), with `ENT_QUOTES` so the encoding covers both single- and double-quoted attribute contexts, and an explicit `UTF-8` encoding to avoid locale-dependent defaults. Encoding at output time rather than input time is the correct place for this control: it neutralizes `<`, `>`, `&`, and quote characters into their HTML entity equivalents so the browser renders them as text instead of parsing them as markup, and it does so without altering the stored/business value of the input for any other consumer. No allowlist or input-stripping was added, since these values (a free-text note, a ticket ID, a name) do not have a fixed format the application can safely constrain.

Verification: request the page with `note` containing `<script>alert(1)</script>` (or `"><img src=x onerror=alert(1)>` for `requester`/`ticket_id`) both before and after the fix. Before the fix, the payload renders as live markup/script in the response body. After the fix, the same payload appears as literal, inert text (`&lt;script&gt;...`) in the rendered output.
