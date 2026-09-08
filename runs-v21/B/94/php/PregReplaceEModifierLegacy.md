## Verdict

exploitable

## Source

**Source**: `$_POST['formatter']` in `handleRenderRequest()` at line 35, flows unvalidated to the `renderUserTemplate()` function parameter `$formatter`.

**Sink**: `preg_replace()` with `/e` modifier at line 24, which evaluates the replacement string as PHP code. The attacker-controlled `$formatter` is concatenated directly into the evaluated code, allowing arbitrary PHP execution.

**Data Flow**: HTTP POST parameter `formatter` → `$formatter` variable → `renderUserTemplate()` parameter → concatenated into `preg_replace()`'s replacement string → evaluated as PHP code

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
    // Allowlist of safe formatter functions
    $allowed_formatters = array('strtoupper', 'strtolower', 'trim', 'ucfirst');
    
    // Validate and constrain $formatter to the allowlist
    if (!in_array($formatter, $allowed_formatters, true)) {
        $formatter = 'strtoupper'; // Default to safe value
    }
    
    // Use preg_replace_callback() instead of /e modifier to avoid code injection
    return preg_replace_callback(
        '/\{(\w+)\}/',
        function($matches) use ($vars, $formatter) {
            $fieldName = $matches[1];
            if (isset($vars[$fieldName])) {
                // Call the allowlisted formatter function
                return $formatter($vars[$fieldName]);
            }
            return $matches[0]; // Return original if field not found
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

The vulnerability stems from using `preg_replace()` with the `/e` modifier, which evaluates the replacement string as PHP code. The attacker-controlled `$formatter` parameter is concatenated directly into this evaluated code, allowing arbitrary PHP execution (e.g., setting `$formatter` to `system('id')` or other malicious code). The fix replaces the dangerous `/e` modifier with `preg_replace_callback()`, which accepts a callable function instead of evaluated code. An allowlist is added to constrain `$formatter` to known safe functions (`strtoupper`, `strtolower`, `trim`, `ucfirst`), preventing any attacker-supplied value from reaching code execution. The callback function handles field substitution safely by calling the allowlisted formatter as a normal function, eliminating the code injection vector entirely.

## Behaviour changes

1. **Allowlist validation added**: `$formatter` must now be one of `strtoupper`, `strtolower`, `trim`, or `ucfirst`. Any other value defaults to `strtoupper`. This constrains what formatters can be applied, which is a product decision intended to prevent injection. The original code had no such validation.

2. **Replacement mechanism changed**: The fix switches from `/e` modifier evaluation to `preg_replace_callback()`. Both achieve the same result for valid fields (applying the formatter function to each matched field), but without dynamic code evaluation. This is a security-driven change and does not alter the visible output for legitimate inputs.

3. **Missing field handling**: When a field name in the template does not exist in the `$vars` array, the original code would create an undefined array access warning and attempt to call the formatter on an undefined value. The fixed code returns the original match unchanged (e.g., `{nonexistent}` remains in the output). This is safer and more correct, avoiding PHP warnings and leaving invalid fields visible rather than corrupting them.

PHP syntax verification: `php -l` returned no syntax errors.
