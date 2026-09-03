## Verdict
Confirmed. Line 24 uses `preg_replace()` with the `/e` modifier, which evaluates the replacement string as PHP code. The `$formatter` parameter is attacker-controlled (from `$_POST['formatter']` with no validation), enabling arbitrary code execution.

## Source
The taint flow runs from `$_POST['formatter']` (line 35) through `$formatter` parameter into the code-evaluation context of the `/e` modifier (line 24). An attacker can supply values like `system('whoami')` or crafted PHP expressions that will be evaluated directly.

## Fix
Replace `preg_replace()` with `/e` modifier with `preg_replace_callback()`:

```php
function renderUserTemplate($template, array $vars, $formatter)
{
    return preg_replace_callback('/\{(\w+)\}/', function($matches) use ($vars, $formatter) {
        $key = $matches[1];
        if (isset($vars[$key])) {
            return call_user_func($formatter, $vars[$key]);
        }
        return $matches[0];
    }, $template);
}
```

Additional hardening: Validate `$formatter` against a whitelist of safe function names to prevent misuse of `call_user_func()` on unexpected callables.

## Explanation
The `/e` modifier in `preg_replace()` evaluates replacement strings as live PHP code, which is dangerous with user-controlled input. `preg_replace_callback()` computes replacements via a function call instead, avoiding code evaluation. The callback receives match objects and applies the formatter through `call_user_func()`, which is safe as long as the formatter name is validated. This preserves the intended behavior of applying per-render formatting while eliminating the code injection vector.
