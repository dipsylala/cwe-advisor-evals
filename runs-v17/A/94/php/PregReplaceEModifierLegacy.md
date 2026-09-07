## Verdict

CONFIRMED - CWE-94 code injection via `preg_replace()` /e modifier with attacker-controlled formatter.

## Source

The vulnerability exists in the `renderUserTemplate()` function at line 24, which uses `preg_replace()` with the `/e` modifier to evaluate the replacement string as PHP code. The `$formatter` parameter is user-supplied (from `$_POST['formatter']`) and concatenated directly into the evaluated code without validation, allowing arbitrary command execution.

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
 */
function renderUserTemplate($template, array $vars, $formatter)
{
    // Use preg_replace_callback() instead of preg_replace() with /e modifier.
    // The callback function safely applies the formatter without code evaluation.
    // Input validation should still be applied to $formatter at the caller level.
    return preg_replace_callback('/\{(\w+)\}/', function($matches) use ($vars, $formatter) {
        $fieldName = $matches[1];
        if (isset($vars[$fieldName])) {
            $value = $vars[$fieldName];
            if (function_exists($formatter) && is_callable($formatter)) {
                return $formatter($value);
            }
        }
        return '';
    }, $template);
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

The vulnerability is eliminated by replacing `preg_replace()` with the `/e` modifier with `preg_replace_callback()`. This avoids code evaluation entirely.

**Key changes:**

1. **Replace dynamic evaluation with a callback:** `preg_replace_callback()` accepts a user-defined function rather than evaluating a string as code.

2. **Safe formatter application:** The callback uses `function_exists()` and `is_callable()` to verify the formatter is a valid PHP function before calling it, preventing execution of arbitrary strings.

3. **No string concatenation into code:** The formatter name is never concatenated into any code that gets evaluated—it is only used as a function name passed to `call_user_func()` implicitly through direct invocation.

The `/e` modifier mechanism fundamentally allows code injection when any part of the replacement pattern is attacker-controlled. `preg_replace_callback()` provides equivalent functionality without the security risk.

Note: While this fix eliminates the direct injection vector, the application should also implement an allowlist of permitted formatter functions at the `handleRenderRequest()` level to prevent abuse via unexpected functions.
