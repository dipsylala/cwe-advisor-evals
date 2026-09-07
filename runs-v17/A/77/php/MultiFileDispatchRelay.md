## Verdict

Real vulnerability confirmed. Untrusted method names flow from user input through a 5-file call chain to a dynamic method invocation with no validation of the method name against a whitelist.

## Source

The vulnerability originates in WorkflowStepController.php, where user-submitted JSON (via `php://input`) contains an `action` field with no restrictions on its content. This action string (e.g., `"email.arbitraryMethod"`) flows unmodified through WorkflowStep as a value object, into WorkflowExecutionService, then to ActionResolver, which splits it on "." and validates only the category prefix against a handler registry. The method name suffix is extracted unvalidated and passed to ActionDispatcher, which invokes it as a dynamic method call: `$handler->$method($params)` (line 12). If the handler object contains any public method accepting the params array (such as one that executes system commands), an attacker can invoke it by controlling the action string.

## Fix

### File: ActionResolver.php

```php
<?php

/**
 * Minimal handler used by the email category. Real deployments have several
 * of these (Sms, Slack, Webhook, ...); only one is included here to keep
 * the example self-contained.
 */
class EmailActionHandler
{
    public function send(array $params): void
    {
        error_log('email.send: ' . ($params['to'] ?? 'unknown'));
    }
}

/**
 * Maps a workflow action string like "email.send" to a handler instance for
 * the "email" category plus the method name within it. The category is
 * checked against a registry; the method half of the string is validated
 * against a whitelist of allowed methods for that category.
 */
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;

    /** @var array<string, list<string>> */
    private array $allowedMethods;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];

        $this->allowedMethods = [
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

        if (!isset($this->allowedMethods[$category]) || !in_array($method, $this->allowedMethods[$category], true)) {
            throw new \RuntimeException("Unknown workflow action: $action");
        }

        return [$this->registry[$category], $method];
    }
}
```

## Explanation

The fix adds a second-layer whitelist, `$allowedMethods`, keyed by category and containing an array of permitted method names for each handler. When resolving an action string, after validating the category exists in the registry, the code now also validates that the method name exists in the corresponding allowedMethods list before returning it for invocation. This ensures that only explicitly permitted methods can be called via the dynamic dispatch, preventing an attacker from invoking arbitrary methods on the handler object, even if the handler exposes public methods not intended as workflow actions. The whitelist is defined in the constructor alongside the registry for ease of maintenance and clarity of intent.
