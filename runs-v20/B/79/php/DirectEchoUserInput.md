## Verdict

Exploitable. CWE-79 (Reflected Cross-Site Scripting), high confidence.

## Source

`$_POST['note']` at `DirectEchoUserInput.php` line 27 - an attacker-controlled POST parameter with no validation or encoding applied anywhere between input and output.

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
$requesterNote = htmlspecialchars($_POST['note'] ?? '', ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
echo "<div class='requester-note'>Note from requester: " . $requesterNote . "</div>";
?>
</body>
</html>
```

## Explanation

Line 27 concatenated `$_POST['note']` straight into the HTML response with no encoding, so a POST body containing `<script>...</script>` or an event-handler payload (e.g. `<img src=x onerror=...>`) executes in the victim's browser exactly as submitted. The fix routes the value through `htmlspecialchars()` with `ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5` and an explicit `'UTF-8'` charset before it reaches the sink: `ENT_QUOTES` neutralizes both `"` and `'` so the payload cannot break out of an attribute even though this particular sink is body text, `ENT_SUBSTITUTE` replaces invalid UTF-8 byte sequences with a placeholder instead of silently truncating the value, and the explicit `'UTF-8'` argument avoids relying on PHP's default encoding. This is the same context-aware encoding call the surrounding code should use at every output point; it was applied here at the reported sink.

## Behaviour changes

- Added `?? ''` when reading `$_POST['note']`, matching the pattern already used for `$_GET['ticket_id']`/`$_GET['requester']` on lines 13-14. This avoids passing `null` into `htmlspecialchars()` (deprecated in PHP 8.1+ for non-nullable internal-function parameters) and avoids an "Undefined array key" warning when the `note` field is omitted; the rendered output for a missing key is unchanged (empty string either way).
- Special characters in a legitimate note (`<`, `>`, `&`, quotes) now render as their literal characters in the page instead of being interpreted as markup - this is the intended effect of the fix, not an unintended side effect. No other output, return value, or control flow changed.
- Lines 22-23 (`$requesterName`, `$ticketId`) are unescaped `$_GET` values with the same class of weakness but are outside the reported finding's sink (line 27) and were left unmodified, consistent with a surgical fix; they would need the same `htmlspecialchars()` treatment in a follow-up pass.

## Verification

`php -l` (PHP 8.5.0 CLI) against the fixed file in a scratch location: "No syntax errors detected". No project test suite was available to exercise the route; the only new call, `htmlspecialchars()` with the constants `ENT_QUOTES`, `ENT_SUBSTITUTE`, `ENT_HTML5`, is a PHP core builtin (no import needed) and matches the signature and flag names given in `cwe/79/php/INDEX.md`.
