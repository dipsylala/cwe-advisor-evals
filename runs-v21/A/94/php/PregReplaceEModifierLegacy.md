## Verdict
VULNERABLE. The `/e` modifier in `preg_replace()` evaluates the replacement string as PHP code. Since `$formatter` is attacker-controlled from `$_POST['formatter']`, arbitrary PHP code can be executed.

## Source
The `$formatter` parameter comes from unsanitized user input at line 35:
```
$formatter = isset($_POST['formatter']) ? $_POST['formatter'] : 'strtoupper';
```

This value is passed directly to `renderUserTemplate()` and concatenated into code that will be evaluated by the `/e` modifier.

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
    // Validate that formatter is a callable function before using it
    if (!is_callable($formatter)) {
        throw new InvalidArgumentException('Formatter must be a valid callable function');
    }

    // Use preg_replace_callback to safely apply the formatter without code evaluation.
    // This avoids the /e modifier (removed in PHP 7.0) which evaluated the replacement
    // string as PHP code, creating a code injection vulnerability.
    return preg_replace_callback(
        '/\{(\w+)\}/',
        function($matches) use ($vars, $formatter) {
            $fieldName = $matches[1];
            if (!isset($vars[$fieldName])) {
                return $matches[0];
            }
            return call_user_func($formatter, $vars[$fieldName]);
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
The `/e` modifier in `preg_replace()` was deprecated in PHP 5.5 and removed in PHP 7.0. It evaluates the replacement string as PHP code, which creates a code injection sink when that string contains attacker-controlled input.

The fix replaces `preg_replace()` with `/e` modifier with `preg_replace_callback()`, which uses a callback function to generate replacements instead of evaluating a string as code. The callback:
1. Extracts the field name from each `{fieldname}` match
2. Retrieves the corresponding value from `$vars`
3. Applies the formatter function via `call_user_func()`
4. Returns the formatted value

Input validation is added via `is_callable()` to ensure only valid callable functions can be used as formatters, preventing the formatter parameter from being exploited as an injection vector. If an invalid formatter is supplied, an exception is thrown rather than attempting code execution.
