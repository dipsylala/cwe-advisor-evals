## Verdict

CONFIRMED - Exploitable command injection via dynamic method dispatch on untrusted input.

## Source

JSON input from HTTP request body (`php://input`), specifically the `action` field provided by the client in WorkflowStepController.php line 16-17.

**Data flow:**
1. WorkflowStepController receives untrusted `action` string from JSON request body
2. WorkflowStep stores this action without validation (line 18 only calls `trim()`)
3. WorkflowExecutionService passes it to ActionResolver::resolve() (line 26)
4. ActionResolver splits on the dot separator and extracts the method name without allowlisting (line 38)
5. ActionDispatcher uses the untrusted method name for variable method invocation (line 12: `$handler->$method()`)

## Fix

Allowlist valid action verbs and their corresponding methods. The ActionResolver must validate the complete action string or at minimum validate that the extracted method name is a recognized operation for the handler category.

**Option 1: Allowlist complete action strings (most restrictive, recommended):**

```php
class ActionResolver
{
    /** @var array<string, object> */
    private array $registry;
    
    /** @var array<string, array{handler: string, method: string}> */
    private array $allowedActions;

    public function __construct()
    {
        $this->registry = [
            'email' => new EmailActionHandler(),
        ];
        
        // Define all valid action strings explicitly
        $this->allowedActions = [
            'email.send' => ['handler' => 'email', 'method' => 'send'],
        ];
    }

    /** @return array{0: object, 1: string} */
    public function resolve(string $action): array
    {
        // Reject if action not in allowlist
        if (!isset($this->allowedActions[$action])) {
            throw new \RuntimeException("Unknown workflow action: $action");
        }
        
        $resolved = $this->allowedActions[$action];
        $category = $resolved['handler'];
        $method = $resolved['method'];

        if (!isset($this->registry[$category])) {
            throw new \RuntimeException("Unknown workflow category: $category");
        }

        return [$this->registry[$category], $method];
    }
}
```

**Option 2: Allowlist methods per category (more flexible if categories are added frequently):**

```php
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
        
        // Define valid methods for each handler category
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
        
        // Validate method against allowlist for this category
        if (!in_array($method, $this->allowedMethods[$category] ?? [], true)) {
            throw new \RuntimeException("Unknown method '$method' for category '$category'");
        }

        return [$this->registry[$category], $method];
    }
}
```

Use Option 1 for tighter control over available operations. Use Option 2 if you are frequently adding new handlers with new methods and want to avoid updating a single large allowlist.

## Explanation

The vulnerability occurs because ActionResolver extracts a method name from untrusted input and returns it without validation. ActionDispatcher then uses this untrusted method name for variable method invocation (`$handler->$method()`), allowing an attacker to call any method on the handler object that they can name.

For example, submitting `{"action":"email.__construct"}` or `{"action":"email.getClass"}` would invoke those methods if they exist, potentially bypassing intended controls or exposing internal state.

The fix applies an allowlist to ensure only recognized, intended methods can be invoked. This breaks the injection chain: untrusted input can no longer determine which method executes; only the resolver's hardcoded allowlist does. The method name passes through the filter before being used in the dispatch call, adhering to the principle: "never let untrusted input choose which function, method or class is invoked directly; only the allowlist lookup result should reach the dispatch call."

## Behaviour changes

- Unknown action verbs now raise `RuntimeException` instead of reaching the dispatch call.
- Action strings outside the allowlist (e.g., `email.send_raw`, `email.__construct`, or `email.nonexistent`) are rejected at the resolver step before any method invocation occurs.
- Legitimate workflows using only the defined actions (`email.send`) work unchanged.
- No changes to ActionDispatcher or WorkflowExecutionService are required; the fix is localized to ActionResolver.
