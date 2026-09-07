## Verdict

exploitable

## Source

`$_POST['formatter']` at line 35 in `handleRenderRequest()` — untrusted user input passed without validation to `renderUserTemplate()`.

## Fix

### File: PregReplaceEModifierLegacy.php

```php
<?php
// Legacy PHP 5.x template renderer.
// Targets PHP 5.x specifically: the preg_replace() /e modifier this file
// relies on was removed in PHP 7.0, so this sink only evaluates on a
// PHP 5.x runtime (e.g. the 5.6 branch still deployed by this application).

/**
 * Renders a simple {field} template, applying a per-render formatter
 * function name to each substituted value (e.g. strtoupper, trim).
 *
 * @param string $template  Template string containing {field} placeholders.
 * @param array  $vars      Field name => value pairs to substitute.
 * @param string $formatter Name of a formatting function to apply to each value.
 * @return string Rendered template.
 * @throws InvalidArgumentException if $formatter is not in the allowlist.
 */
function renderUserTemplate($template, array $vars, $formatter)
{
    // Allowlist of permitted formatter functions
    $allowedFormatters = array(
        'strtoupper' => 'strtoupper',
        'strtolower' => 'strtolower',
        'trim' => 'trim',
        'ucfirst' => 'ucfirst',
        'lcfirst' => 'lcfirst',
    );
    
    // Validate formatter is in the allowlist
    if (!isset($allowedFormatters[$formatter])) {
        throw new InvalidArgumentException('Invalid formatter: ' . $formatter);
    }
    
    $safeFormatter = $allowedFormatters[$formatter];
    
    // Use preg_replace_callback() instead of /e modifier to avoid code injection.
    // The callback receives match objects; the formatter function is called via
    // call_user_func() with the matched value, not evaluated as PHP code.
    return preg_replace_callback(
        '/\{(\w+)\}/',
        function($matches) use ($vars, $safeFormatter) {
            $fieldName = $matches[1];
            if (!isset($vars[$fieldName])) {
                return '';
            }
            return call_user_func($safeFormatter, $vars[$fieldName]);
        },
        $template
    );
}

/**
 * HTTP handler: renders a user-supplied template using a user-chosen
 * formatter function name. Both the template text and the formatter name
 * come straight from the POST body with no allowlist or validation.
 */
function handleRenderRequest()
{
    $template  = isset($_POST['template']) ? $_POST['template'] : '';
    $formatter = isset($_POST['formatter']) ? $_POST['formatter'] : 'strtoupper';
    $vars      = (isset($_POST['vars']) && is_array($_POST['vars'])) ? $_POST['vars'] : array();

    echo renderUserTemplate($template, $vars, $formatter);
}
```

## Explanation

The vulnerability arises because `preg_replace()` with the `/e` modifier evaluates the replacement string as PHP code. The original code concatenates the untrusted `$formatter` parameter directly into the evaluated replacement string: `$formatter . '($vars["$1"])'`. An attacker can submit `formatter=system` to execute system commands, or use any other callable function to achieve arbitrary code execution. The fix replaces `preg_replace()` with the dangerous `/e` modifier using `preg_replace_callback()`, which accepts a regular callback function instead of evaluating a code string. The callback invokes the formatter function via `call_user_func()`, which is safe. Additionally, an allowlist validation is added so only permitted formatter functions (`strtoupper`, `strtolower`, `trim`, `ucfirst`, `lcfirst`) can be used; any other value raises an `InvalidArgumentException`, preventing the injection entirely.

## Behaviour changes

The function now throws `InvalidArgumentException` when the formatter parameter does not match an entry in the allowlist. This is a breaking change for any caller that previously passed an invalid formatter name; however, the original code would have produced a PHP error or unexpected output in such cases, so the new behavior is stricter but more predictable. Callers relying on custom formatter functions must add them to the allowlist before use. The return value and template rendering logic remain functionally identical for allowlisted formatters.
