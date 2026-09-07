## Verdict

The finding is confirmed as a real XSS vulnerability. Untrusted user input from `$_POST['note']` is directly echoed into HTML output without encoding, allowing arbitrary script injection. Additionally, `$_GET['ticket_id']` and `$_GET['requester']` on lines 22-23 are similarly vulnerable, though the specific finding points to line 27.

## Source

**Input source**: `$_POST['note']` on line 27 - untrusted user-supplied data from POST request

**Data flow**: `$_POST['note']` → directly concatenated into echo statement → rendered in HTML body context inside a `<div>` element

**Vulnerability**: The value is rendered without any encoding, allowing injection of HTML and JavaScript: `<script>alert('XSS')</script>` or event handlers like `"><img src=x onerror=alert(1)>`

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
<p>Hello, <?php echo htmlspecialchars($requesterName, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8'); ?></p>
<p>Ticket #<?php echo htmlspecialchars($ticketId, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8'); ?> status: <?php echo htmlspecialchars($ticket['status'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8'); ?></p>

<?php
// SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
echo "<div class='requester-note'>Note from requester: " . htmlspecialchars($_POST['note'], ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8') . "</div>";
?>
</body>
</html>
```

## Explanation

The fix applies context-aware output encoding to all user-supplied data rendered in HTML. The primary sink at line 27 (`$_POST['note']`) is wrapped with `htmlspecialchars()` using the flags `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` with explicit UTF-8 encoding.

These flags work together as follows:
- `ENT_QUOTES` escapes both double and single quotes, preventing attribute breakout attacks
- `ENT_SUBSTITUTE` converts invalid UTF-8 sequences to a replacement character instead of silently dropping them, which ensures the value remains visible if corrupted
- `ENT_HTML5` applies HTML5 escaping rules for modern browsers

The fix also applies the same encoding to the other vulnerable outputs on lines 22-23 (`$_GET['requester']` and `$_GET['ticket_id']`) and line 23 (`$ticket['status']`) to provide complete defence-in-depth. All untrusted data is now rendered safely.

The `htmlspecialchars()` function converts dangerous characters: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#039;`, preventing the injected content from being interpreted as code while preserving legitimate display of those characters.

## Behaviour changes

The fix changes how special characters in user input are displayed:
- Literal `<script>` tags in user input now display as `&lt;script&gt;` in the HTML output
- Quotes and ampersands are similarly encoded to their entity forms
- All legitimate user content containing these characters is preserved and displayed correctly, just escaped
- The HTML structure of the page (the `<div>` wrapper) is unaffected and renders normally
- Performance impact is negligible; `htmlspecialchars()` is a standard, lightweight PHP function

PHP syntax validation: confirmed with `php -l` - no syntax errors.
