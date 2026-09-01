## Verdict

Exploitable

## Source

`$_POST['macro']` at line 16 - untrusted user input from HTTP POST parameter

## Fix

**Vulnerable code:**
```php
$macro = $_POST['macro'];

if ($macro === '') {
    return;
}

// SAST FINDING: CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) reported here. Sink is the next statement.
$renderer->$macro();
```

**Fixed code:**
```php
$macro = $_POST['macro'];

if ($macro === '') {
    return;
}

// Allowlist of known, safe methods
$allowedMacros = [
    'refresh' => 'refresh',
    'exportCsv' => 'exportCsv',
    'purgeCache' => 'purgeCache',
    'deleteReport' => 'deleteReport',
];

// Validate against allowlist and get the canonical method name
if (!isset($allowedMacros[$macro])) {
    throw new Exception("Unknown macro: " . htmlspecialchars($macro));
}

// Call using the allowlist-selected method name
$renderer->$allowedMacros[$macro]();
```

## Explanation

The original code performs dynamic method invocation directly on untrusted input, allowing an attacker to call any public method on the ReportRenderer object by passing a different method name in the POST parameter. The fix implements an allowlist of known safe methods as an associative array, validates the input against it, and uses only the allowlist-selected canonical method name in the dispatch call. This breaks the taint chain by ensuring the dynamic invocation always references a predetermined set of methods, never an arbitrary method from user input. The exception with HTML-escaped output enables audit logging of rejected commands.

## Behaviour changes

The fixed code rejects unknown macro values with an exception, whereas the original code would silently invoke any callable method. This is a necessary security hardening that changes application behavior: calls with invalid macro names now fail loudly and can be logged, rather than potentially executing unintended methods. Legitimate callers passing only the four allowlisted verbs ('refresh', 'exportCsv', 'purgeCache', 'deleteReport') observe no functional change.
