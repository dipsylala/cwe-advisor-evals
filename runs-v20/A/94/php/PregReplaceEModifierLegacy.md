## Verdict

Confirmed. `renderUserTemplate()` uses `preg_replace()` with the deprecated `/e` modifier, which evaluates the replacement string as PHP code for every regex match. The replacement string is built by concatenating `$formatter` - a value taken directly from `$_POST['formatter']` in `handleRenderRequest()` with no allowlist or validation - into that evaluated code. An attacker can supply a formatter value such as `system` combined with a crafted template, or append extra PHP syntax after the closing parenthesis, to execute arbitrary code on the server.

## Source

`$_POST['formatter']` in `handleRenderRequest()` (and `$_POST['template']`, `$_POST['vars']`) flow unvalidated into `renderUserTemplate($template, $vars, $formatter)`, where `$formatter` is concatenated into the `/e`-evaluated replacement string passed to `preg_replace()`.

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
    // The replacement is no longer evaluated as code. preg_replace_callback()
    // runs an ordinary PHP callback per match instead of the /e modifier's
    // "eval the replacement string" behavior, which removes the code
    // injection sink outright rather than trying to sanitize $formatter.
    //
    // $formatter still selects which function runs, so it is resolved
    // against a fixed allowlist of known-safe formatters rather than being
    // invoked directly. An unrecognized value falls back to the same
    // default ('strtoupper') handleRenderRequest() already uses when the
    // POST field is absent, so every legitimate caller keeps working.
    $allowedFormatters = array(
        'strtoupper'       => 'strtoupper',
        'strtolower'       => 'strtolower',
        'trim'             => 'trim',
        'ucfirst'          => 'ucfirst',
        'ucwords'          => 'ucwords',
        'htmlspecialchars' => 'htmlspecialchars',
    );

    $formatterFn = isset($allowedFormatters[$formatter])
        ? $allowedFormatters[$formatter]
        : $allowedFormatters['strtoupper'];

    return preg_replace_callback(
        '/\{(\w+)\}/',
        function ($matches) use ($vars, $formatterFn) {
            $field = $matches[1];
            $value = isset($vars[$field]) ? $vars[$field] : '';
            return $formatterFn($value);
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

The root cause is the `/e` modifier itself, not merely the missing validation on `$formatter` - `/e` compiles and executes its replacement string as PHP source on every match, so any code reachable through that string runs regardless of what value `$formatter` holds. Replacing `preg_replace('/\{(\w+)\}/e', ...)` with `preg_replace_callback('/\{(\w+)\}/', ...)` removes the eval step entirely: the callback receives the match as data and returns a string, and nothing derived from user input is ever parsed as PHP source. This also keeps the fix valid if the application is later moved off the PHP 5.x branch, since `/e` was removed in PHP 7.0 while `preg_replace_callback()` is unaffected.

With the eval sink gone, `$formatter` is still attacker-controlled input used to pick which function executes, so it is resolved through a fixed allowlist (`$allowedFormatters`) rather than passed to a dynamic call unchecked - that closes the separate risk of an attacker naming an unexpected callable (e.g. `system`, `exec`, or any other function reachable by name) even in a variant of this code that called `$formatter(...)` directly instead of evaluating it. An unrecognized formatter name falls back to `strtoupper`, matching the existing default behavior in `handleRenderRequest()` when the POST field is missing, so no legitimate caller's output changes.

A test that reproduces the original bug should POST `formatter=system` with a template like `{cmd}` and `vars[cmd]=id`, confirming the original code executes the shell command while the fixed code instead uppercases the literal fallback output; a second test with `formatter=ucwords` confirms normal formatting still works unchanged.
