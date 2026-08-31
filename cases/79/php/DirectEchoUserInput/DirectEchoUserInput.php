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
<p>Hello, <?php echo $requesterName; ?></p>
<p>Ticket #<?php echo $ticketId; ?> status: <?php echo $ticket['status']; ?></p>

<?php
// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo "<div class='requester-note'>Note from requester: " . $_POST['note'] . "</div>";
?>
</body>
</html>
