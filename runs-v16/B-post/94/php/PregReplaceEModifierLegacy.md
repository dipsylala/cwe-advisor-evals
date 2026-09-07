## Verdict
Exploitable. The `$formatter` parameter is derived directly from `$_POST['formatter']` in `handleRenderRequest()` on line 35, passed without validation to `renderUserTemplate()`, and concatenated into a PHP code string that is evaluated by the `/e` modifier in `preg_replace()` on line 24. An attacker can supply `formatter=system` or any callable function name to execute arbitrary code in the application's runtime context.

## Source
- **Data origin (untrusted input)**: Line 35, `$_POST['formatter']` with a default value of `'strtoupper'` but no validation against user-supplied values; line 34, `$_POST['template']` from the POST body.
- **Intermediate**: Line 38, passed directly to `renderUserTemplate()` with no allowlist or validation.
- **Sink**: Line 24, the replacement string `$formatter . '($vars["$1"])'` is evaluated as PHP code by the `/e` modifier in `preg_replace()`.

## Fix

**Vulnerable Code:**
```php
function renderUserTemplate($template, array $vars, $formatter)
{
    // The /e modifier evaluates the replacement string as PHP code for
    // every match. $formatter is attacker-controlled (see
    // handleRenderRequest() below) and is concatenated directly into that
    // evaluated code, so a formatter value such as "system" - or one that
    // appends extra PHP after the closing paren - runs arbitrary code.
    // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    return preg_replace('/\{(\w+)\}/e', $formatter . '($vars["$1"])', $template);
}

function handleRenderRequest()
{
    $template  = isset($_POST['template']) ? $_POST['template'] : '';
    $formatter = isset($_POST['formatter']) ? $_POST['formatter'] : 'strtoupper';
    $vars      = (isset($_POST['vars']) && is_array($_POST['vars'])) ? $_POST['vars'] : array();

    echo renderUserTemplate($template, $vars, $formatter);
}
```

**Fixed Code:**
```php
function renderUserTemplate($template, array $vars, $formatter)
{
    // Allowlist of permitted formatter functions to prevent code injection.
    // Only safe, built-in string functions are permitted.
    $allowedFormatters = ['strtoupper', 'strtolower', 'trim', 'ucfirst', 'lcfirst'];
    
    if (!in_array($formatter, $allowedFormatters, true)) {
        throw new InvalidArgumentException("Formatter '$formatter' is not allowed");
    }
    
    // Use preg_replace_callback() instead of /e modifier to safely apply the formatter
    // without evaluating arbitrary code.
    return preg_replace_callback('/\{(\w+)\}/', function($matches) use ($vars, $formatter) {
        $fieldName = $matches[1];
        if (!isset($vars[$fieldName])) {
            return $matches[0];
        }
        return $formatter($vars[$fieldName]);
    }, $template);
}

function handleRenderRequest()
{
    $template  = isset($_POST['template']) ? $_POST['template'] : '';
    $formatter = isset($_POST['formatter']) ? $_POST['formatter'] : 'strtoupper';
    $vars      = (isset($_POST['vars']) && is_array($_POST['vars'])) ? $_POST['vars'] : array();

    try {
        echo renderUserTemplate($template, $vars, $formatter);
    } catch (InvalidArgumentException $e) {
        http_response_code(400);
        echo "Error: " . htmlspecialchars($e->getMessage());
    }
}
```

## Explanation
The vulnerability is eliminated by replacing the `/e` modifier in `preg_replace()` with `preg_replace_callback()`, which does not evaluate the replacement string as PHP code. Instead, the replacement is performed by a callback function that receives the matched field name and applies the formatter through a function call, not through code generation. The fix additionally validates that the `$formatter` parameter is in an allowlist of safe, built-in functions before use, rejecting any attempt to pass dangerous functions like `system`, `exec`, or `passthru`. The allowlist is enforced with `in_array(..., true)` for strict type matching, preventing an attacker from injecting a callable object or type-coercion bypass. Error handling is added to gracefully reject invalid formatter names by throwing an `InvalidArgumentException`, which is caught in the HTTP handler and returned as a 400 error to the client rather than allowing the application to crash or silently succeed with an injection.

## Behaviour changes

- **Allowlist validation on formatter**: The fixed code validates that `$formatter` is a member of `$allowedFormatters` before use, raising an `InvalidArgumentException` if it is not. The original code accepted any string and attempted to evaluate it as PHP code. This closes the injection vector but changes the application's contract: callers passing formatters outside the allowlist (e.g., custom user-defined functions) will now fail with an exception instead of succeeding. The allowlist can be extended with additional safe, built-in functions as needed, but custom or arbitrary formatters must be rejected.
- **Callback-based substitution**: The original code used `preg_replace()` with the `/e` modifier, which constructs a PHP expression string and evaluates it. The fixed code uses `preg_replace_callback()` with a closure that invokes the formatter directly. Both produce the same output when the formatter is valid and the field is present, but the fixed code avoids code generation and evaluation entirely.
- **Missing field handling**: If a field name in the template does not exist in `$vars`, the original code would produce an undefined index notice (or error, depending on PHP's error reporting level) and substitute an empty string or error message. The fixed code returns the original placeholder unmodified (e.g., `{fieldname}` stays as-is). This prevents information leakage through error messages but changes the template rendering behavior: malformed templates will now visibly display unsubstituted placeholders instead of failing silently. This is a safer default for a template engine, as it makes template errors visible to the developer.
- **Error handling in HTTP handler**: The original code does not catch exceptions from `renderUserTemplate()`. The fixed code wraps the call in a try-catch block, catches `InvalidArgumentException`, and returns a 400 HTTP response with an error message. This prevents the application from crashing with an unhandled exception if an invalid formatter is supplied, providing graceful client feedback instead.
