## Verdict

Real CWE-77 command injection vulnerability. The `$method` variable in ActionDispatcher line 12 is derived from user input and never validated against an allowlist before use in dynamic method invocation.

## Source

Data originates in `WorkflowStepController::handleStepRequest()` at line 19 where the `action` parameter is read from untrusted JSON without restricting the method portion to a known set of safe operation names.

The action string flows through:
- `WorkflowStep` (line 29) — only trims, does not validate
- `WorkflowExecutionService::execute()` (line 26) — passes action to resolver
- `ActionResolver::resolve()` (line 36-45) — splits action into category and method; validates category against registry but explicitly does not validate method (line 44 comment confirms this gap)
- `ActionDispatcher::dispatch()` (line 12) — receives untrusted method name

## Fix

Add per-handler method whitelists to the resolver. Each handler should declare which methods it permits. When resolving an action, validate the method name against the handler's declared whitelist before returning it. Reject the action if the method is not in the whitelist.

```php
// Modify ActionResolver to include method validation:

class EmailActionHandler
{
    public const ALLOWED_METHODS = ['send'];
    
    public function send(array $params): void
    {
        error_log('email.send: ' . ($params['to'] ?? 'unknown'));
    }
}

class ActionResolver
{
    private array $registry;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];
    }

    public function resolve(string $action): array
    {
        $parts = explode('.', $action, 2);
        $category = $parts[0];
        $method = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        $handler = $this->registry[$category];
        $allowed = $handler::ALLOWED_METHODS ?? [];
        
        if (!in_array($method, $allowed, true)) {
            throw new \RuntimeException("Unknown method '$method' for category '$category'");
        }

        return [$handler, $method];
    }
}
```

## Explanation

Dynamic method invocation (`$handler->$method()`) is inherently risky when `$method` comes from untrusted input. Even if the handler object is trusted, an attacker can call unintended methods like `__toString`, `__invoke`, or other magic methods to achieve unintended behavior.

The fix enforces a whitelist: each handler class declares exactly which public methods it permits to be called via the workflow action syntax. The resolver checks this whitelist before returning the method name to the dispatcher. This ensures only the intended operations can be invoked, preventing an attacker from calling arbitrary or magic methods on the handler.

The whitelist is defined per-handler as a class constant so it stays in sync with the handler's actual capabilities and is not maintained in a separate, error-prone configuration file.
