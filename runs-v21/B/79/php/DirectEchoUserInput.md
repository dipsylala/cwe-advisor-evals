## Verdict

VULNERABLE. CWE-79 (Cross-Site Scripting) confirmed at line 27. The `$_POST['note']` parameter is directly echoed into HTML without any encoding, allowing an attacker to inject malicious scripts that execute in victims' browsers.

## Source

The vulnerability originates from `$_POST['note']` (line 27), an untrusted user input from an HTTP POST request, which flows directly into an HTML `echo` statement without any sanitization or encoding.

**Data flow**: User submits POST request → `$_POST['note']` accessed → concatenated directly into HTML output via `echo`.

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
<p>Hello, <?php echo $requesterName; ?></p>
<p>Ticket #<?php echo $ticketId; ?> status: <?php echo $ticket['status']; ?></p>

<?php
// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($_POST['note'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . "</div>";
?>
</body>
</html>
```

## Explanation

The fix applies `htmlspecialchars()` with the flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and explicit UTF-8 encoding to the `$_POST['note']` value before echoing it into HTML. This converts special HTML characters—`<`, `>`, `&`, `"`, and `'`—into their corresponding HTML entities (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#039;`), preventing the browser from interpreting user-supplied content as executable code.

- `ENT_QUOTES`: Escapes both double and single quotes, preventing attribute breakout.
- `ENT_SUBSTITUTE`: Replaces invalid UTF-8 sequences with a replacement character rather than silently dropping them, ensuring data is always present and visible.
- `ENT_HTML5`: Uses HTML5 named entity definitions.
- `'UTF-8'`: Explicitly specifies character encoding to prevent encoding-based bypasses.

The fix preserves the existing HTML structure and output format—only the user-supplied content is encoded, not the surrounding markup. Legitimate content containing special characters (e.g., mathematical symbols, email addresses with `@`) renders correctly as text rather than as markup.

PHP syntax verified with `php -l`.

## Behaviour changes

**Output before fix**: Raw HTML and user input
```
Note from requester: <script>alert('XSS')</script>
```
Browser interprets `<script>` as executable code; malicious script runs.

**Output after fix**: Escaped HTML entities
```
Note from requester: &lt;script&gt;alert('XSS')&lt;/script&gt;
```
Browser renders entities as literal text; the script tag appears as plain text in the page, not executable.

Users submitting content with legitimate special characters (e.g., "Price is $50 & worth it") will see those characters correctly displayed as encoded entities in the HTML, with no visual difference in the rendered page.
