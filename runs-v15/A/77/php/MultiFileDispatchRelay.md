## Verdict
Real vulnerability confirmed. The `$method` variable used in the dynamic method call at line 12 of ActionDispatcher.php originates from user-supplied input in the `action` JSON field, passed through WorkflowStepController → WorkflowStep → WorkflowExecutionService → ActionResolver without validation. An attacker can invoke arbitrary methods on handler objects.

## Source
User-controlled `action` string flows from WorkflowStepController line 29 (`$body['action']`) through WorkflowStep to ActionResolver, where it is split by dot and the method portion extracted at line 38 without validation. The comment at ActionResolver line 44 explicitly acknowledges the lack of validation: "// $method still carries whatever the caller wrote after the dot." This unvalidated method name reaches ActionDispatcher line 12 where it is invoked dynamically: `$handler->$method($params)`.

## Fix
Add method whitelisting to ActionResolver. Define an allowed method list for each handler category and validate the requested method against it before returning:

```php
class ActionResolver
{
    private array $registry;
    private array $allowedMethods = [
        'email' => ['send', 'handle'],
    ];

    public function resolve(string $action): array
    {
        $parts = explode('.', $action, 2);
        $category = $parts[0];
        $method = $parts[1] ?? 'handle';

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        if (!isset($this->allowedMethods[$category]) || 
            !in_array($method, $this->allowedMethods[$category], true)) {
            throw new \RuntimeException(
                "Unknown or forbidden workflow action: $action"
            );
        }

        return [$this->registry[$category], $method];
    }
}
```

Alternatively, use reflection to allow only explicitly marked safe methods:

```php
public function resolve(string $action): array
{
    $parts = explode('.', $action, 2);
    $category = $parts[0];
    $method = $parts[1] ?? 'handle';

    if (!isset($this->registry[$category])) {
        throw new \RuntimeException("Unknown workflow category: $category");
    }

    $handler = $this->registry[$category];
    if (!method_exists($handler, $method) || 
        !is_callable([$handler, $method]) ||
        strpos($method, '_') === 0) {
        throw new \RuntimeException(
            "Unknown or forbidden workflow action: $action"
        );
    }

    return [$handler, $method];
}
```

The first approach (whitelist) is more secure as it explicitly controls which methods are exposed to workflow automation.

## Explanation
CWE-77 occurs when user-supplied input is used to invoke operations (in this case, methods) without neutralizing special elements or validating against an allowed set. The workflow dispatcher accepts an `action` string from the user, splits it to extract a category and method name, but only validates the category against a known handler registry. The method name is never validated, allowing an attacker to invoke any public method on a handler object—including unintended ones like `__construct`, `__call`, `__toString`, or internal methods.

The remediation enforces that only explicitly whitelisted methods can be invoked through the workflow system. This maintains the intended design (category-based dispatch) while preventing misuse of the dynamic method call mechanism. The whitelist approach scales as new handlers and methods are added, since the allowed methods must be explicitly declared for each category.
