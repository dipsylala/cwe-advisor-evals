## Verdict

The vulnerability is **exploitable**. An attacker-controlled action string from the HTTP request body reaches a dynamic method dispatch with no validation of the method name. The category is validated against a handler registry, but the method extracted after the dot carries whatever the caller provided without restriction, allowing invocation of any method on the handler object.

## Source

Untrusted input enters at `WorkflowStepController::handleStepRequest()` (line 29):
- HTTP POST body `$body['action']` (from `json_decode()` of `php://input`)
- No method-level validation on the action string at this point; only shape validation (must be string)
- Passed to `WorkflowStep` constructor, stored in `$this->action` with only `trim()` applied
- Flows through `WorkflowExecutionService::execute()` which calls `$this->resolver->resolve($step->getAction())`
- In `ActionResolver::resolve()`, the action is split on the first dot: `$parts = explode('.', $action, 2)`
  - Category (before dot) is validated: checked against `$this->registry` via `isset()`
  - Method (after dot) is NOT validated: `$method = $parts[1] ?? 'handle'` is returned as-is
  - Comment in ActionResolver line 44 explicitly notes: "$method still carries whatever the caller wrote after the dot"
- Returned as-is to `WorkflowExecutionService::dispatch()` which passes it to `ActionDispatcher::dispatch()`

## Fix

**Vulnerable code** in `ActionResolver::resolve()` (lines 34–46):

```php
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
```

**Fixed code:**

```php
/** @var array<string, array<string>> */
private array $methodAllowlist = [
    'email' => ['send'],
];

/** @return array{0: object, 1: string} */
public function resolve(string $action): array
{
    $parts = explode('.', $action, 2);
    $category = $parts[0];
    $method = $parts[1] ?? 'handle';

    if (!isset($this->registry[$category])) {
        throw new \RuntimeException("Unknown workflow category: $category");
    }

    // Validate method against allowlist for the category
    if (!isset($this->methodAllowlist[$category]) || 
        !in_array($method, $this->methodAllowlist[$category], true)) {
        throw new \RuntimeException("Unauthorized action method: $category.$method");
    }

    return [$this->registry[$category], $method];
}
```

The `$methodAllowlist` property is a map from category name to an array of allowed method names for that category. The allowlist is checked using `in_array()` with strict comparison (`true` parameter) to prevent type juggling attacks. Any method not explicitly listed is rejected before it reaches the dispatcher.

## Explanation

The vulnerability stems from trusting untrusted input to select which method to invoke on a handler object via dynamic dispatch (`$handler->$method()`). The category part of the action string is validated against a known registry of handlers, but the method part—the part that determines which function actually runs—is not. An attacker can supply any method name they want, including private methods, magic methods, or methods inherited from parent classes, causing code execution paths the application did not intend to expose.

The fix establishes an explicit allowlist of methods per category. Only methods named in this allowlist can be invoked; any other method name in an action string is rejected with an exception. This follows the CWE-77 PHP guidance principle: "map each recognised command verb to a specific, hardcoded handler via an explicit allowlist array, never via `call_user_func()` or variable-function/variable-variable dispatch on untrusted input." The allowlist breaks the taint chain by ensuring that the method name used in the sink (`$handler->$method()`) is always one of the few values the application explicitly permits, not any value an attacker can craft.

## Behaviour changes

The fixed code adds validation that was not present before. The original code would attempt dynamic dispatch on any method name supplied by the caller; the fixed code throws a `RuntimeException` for any method not in the allowlist.

- **New exception:** Unknown or unauthorized methods (e.g., `email.__construct`, `email.errorHandler`) now raise `RuntimeException` before the method is invoked. This is a rejection-based control (fail closed): invalid inputs are refused outright rather than processed. Legitimate calls using only whitelisted methods (e.g., `email.send`) continue to work as before.
- **No change to return value or caller contract:** The dispatcher still receives the same pair—a handler object and a validated method name—so the downstream dispatch in `ActionDispatcher::dispatch()` line 12 remains unchanged.
- **No change to error handling in the dispatcher:** The exception is thrown in the resolver before the dispatcher is called, so error-handling paths in `ActionDispatcher` are unaffected.
- **New assertion:** The application now formally requires that every handler category have an entry in `$methodAllowlist`. If a new category is added to `$this->registry` without an entry in the allowlist, actions for that category will always be rejected—this is intentional and forces developers to explicitly declare which methods are safe for each category.
