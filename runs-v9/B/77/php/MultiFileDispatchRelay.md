## Verdict

Exploitable. CWE-77 (Improper Neutralization of Special Elements used in a Command). Confidence: high.

## Source

`WorkflowStepController::handleStepRequest()` reads the raw HTTP request body (`file_get_contents('php://input')`), JSON-decodes it, and takes `$body['action']` unmodified. The only check is that it is a non-empty string; its content is never restricted to a known verb. That value is wrapped in a `WorkflowStep` (which likewise only trims it, applying no allowlist) and reaches `WorkflowExecutionService::execute()`, which calls `$this->resolver->resolve($step->getAction())`.

Call chain: `WorkflowStepController::handleStepRequest()` -> `WorkflowStep` (holds `$action`) -> `WorkflowExecutionService::execute()` -> `ActionResolver::resolve()` -> `ActionDispatcher::dispatch()`.

In `ActionResolver::resolve()`, the string is split on the first `.`: the part before it (`$category`) is checked against a registry allowlist (`isset($this->registry[$category])`), but the part after it (`$method`) is taken as-is with no validation - the code comment even notes "`$method` still carries whatever the caller wrote after the dot." Both the resolved handler object and this unvalidated `$method` string are returned to the caller and passed straight into `ActionDispatcher::dispatch()`.

## Fix

Vulnerable code (`ActionResolver.php`):

```php
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];
    }

    /** @return array{0: object, 1: string} */
    public function resolve(string $action): array
    {
        $parts = explode('.', $action, 2);
        $category = $parts[0];
        $method = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        // $method still carries whatever the caller wrote after the dot.
        return [$this->registry[$category], $method];
    }
}
```

Then, unchanged but shown for context, the sink (`ActionDispatcher.php` line 12):

```php
public function dispatch(object $handler, string $method, array $params): void
{
    $handler->$method($params);
}
```

Fixed code (`ActionResolver.php`) - only this file changes; `ActionDispatcher.php` is left as-is because the taint is broken before the dispatch call is ever reached:

```php
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /**
     * Explicit allowlist of the only methods each category's handler may be
     * dispatched to. Add a new category here only alongside a new registry
     * entry and its own list of permitted method names.
     *
     * @var array<string, array<string, string>>
     */
    private array $allowedMethods;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];

        $this->allowedMethods = [
            'email' => ['send' => 'send'],
        ];
    }

    /** @return array{0: object, 1: string} */
    public function resolve(string $action): array
    {
        $parts = explode('.', $action, 2);
        $category = $parts[0];
        $requestedMethod = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        if (!isset($this->allowedMethods[$category][$requestedMethod])) {
            throw new \RuntimeException("Unknown workflow action: $action");
        }

        // Canonical value selected from the allowlist, not the raw input.
        $method = $this->allowedMethods[$category][$requestedMethod];

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

`$handler->$method($params)` is a dynamic method call whose method name came straight from attacker-controlled HTTP input, with only the category half of that input checked against an allowlist. Because a callable string in PHP is not limited to the verbs the application intends - any public method name on the resolved object can be selected this way - an attacker could invoke any public method the target handler class happens to expose (including inherited or unintended ones on richer handlers, per the file's own note that real deployments have several handler classes), not just the `send` action the workflow builder is supposed to offer. The fix adds a second allowlist, keyed by category, that maps each caller-supplied verb to the one canonical method name that category is permitted to invoke. Only a value taken from this map - never the original `$requestedMethod` string - is returned and passed on to `ActionDispatcher::dispatch()`, so the dynamic call at the sink can only ever land on a method the application explicitly enumerated. Unknown verbs are rejected with a `RuntimeException` before the handler is ever touched.

## Behaviour changes

- An action whose verb is not in the new per-category allowlist (e.g. `email.delete`, or any verb other than `send` under `email`) now throws `RuntimeException("Unknown workflow action: ...")` from `ActionResolver::resolve()`. Previously such a call would reach `$handler->$method(...)` and fail there instead - with a plain PHP `Error: Call to undefined method` for any method that doesn't exist on the handler, or, for the vulnerability this fix closes, would have succeeded in calling a method that does exist but was never meant to be reachable this way. Rejecting earlier with a clear exception is the intended effect of the fix, not incidental.
- An action with no `.` in it defaults `$requestedMethod` to `'handle'` as before, but `'handle'` is not present in the `email` allowlist, so it now fails with the same `RuntimeException` rather than falling through to a call that would previously have thrown an undefined-method `Error` anyway (no handler in this file defines a `handle()` method). Net effect on legitimate traffic is none; the failure mode for this already-broken input is now controlled instead of a raw engine error.
- No change to `ActionDispatcher::dispatch()`'s signature, return value (`void`), or argument order - the sink's contract is preserved exactly; only the value it receives for `$method` is now guaranteed to come from the allowlist.
