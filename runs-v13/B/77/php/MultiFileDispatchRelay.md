## Verdict

Exploitable

## Source

User-supplied action string from JSON input in `WorkflowStepController::handleStepRequest()` (line 17: `$body = json_decode($raw, true)`). The action string is passed as-is through `WorkflowStep` and `WorkflowExecutionService` to `ActionResolver::resolve()`, where it is split by dot separator. The method portion (right of the dot) is extracted without validation.

## Fix

**Vulnerable Code (ActionResolver.php):**
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

**Fixed Code (ActionResolver.php):**
```php
/** @var array<string, array<string>> Map of category to allowed methods */
private array $allowlist;

public function __construct()
{
    $this->registry = [
        'email' => new EmailActionHandler(),
    ];
    
    // Allowlist: map each category to its permitted handler methods
    $this->allowlist = [
        'email' => ['send'],
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

    // Validate method against allowlist for this category
    if (!isset($this->allowlist[$category]) || !in_array($method, $this->allowlist[$category], true)) {
        throw new \RuntimeException("Unknown workflow action: $action");
    }

    return [$this->registry[$category], $method];
}
```

## Explanation

The vulnerability is that the `$method` string returned by `ActionResolver::resolve()` is derived entirely from user input after minimal validation (only the category part is checked). This untrusted value then reaches the sink at `ActionDispatcher::dispatch()` line 12, where it is used in variable method invocation: `$handler->$method($params)`. An attacker can supply an action string like "email.__destruct" or "email.__toString" to invoke arbitrary methods on the handler object, or attempt to reference methods that do not exist (potentially triggering `__call()` magic methods if defined).

The fix adds an explicit allowlist in `ActionResolver` that maps each category to the set of permitted handler methods for that category. Only methods present in the allowlist are allowed to reach the dispatcher. The method validation happens after the category validation and before the tuple is returned, so the dispatcher receives only a method name that has been explicitly approved. An action string with a method not in the allowlist throws a `RuntimeException`, rejecting the request early with a clear error.

## Behaviour changes

None. The fix preserves the existing contract: `ActionResolver::resolve()` still returns a tuple of handler and method name, both strings. The exception type and message change when an invalid action is submitted (from "Unknown workflow category" to "Unknown workflow action"), but invalid actions result in an exception either way. Legitimate workflow actions within the allowlist ("email.send") continue to work identically. The downstream consumer (`ActionDispatcher`) receives only validated method names and behaves exactly as before.
