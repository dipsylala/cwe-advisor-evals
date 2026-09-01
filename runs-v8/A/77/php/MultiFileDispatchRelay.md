## Verdict
CONFIRMED. The `$method` parameter in ActionDispatcher::dispatch() is derived from untrusted user input and used in a dynamic method invocation without validation.

## Source
The vulnerability originates in WorkflowStepController, which receives an untrusted `action` string from JSON input (line 17-19). This action is passed through WorkflowStep to WorkflowExecutionService::execute() (line 26), where ActionResolver::resolve() splits it on the dot delimiter (line 36). ActionResolver validates only the category (before the dot) against a registry (line 40), but returns the method portion (after the dot) completely unvalidated (line 45). This unvalidated method name flows to ActionDispatcher::dispatch() (line 12 of ActionDispatcher.php), where it is used in a dynamic method invocation: `$handler->$method($params)`.

## Fix
Validate the method name in ActionDispatcher before executing the dynamic invocation. Add validation to ensure the method name contains only valid PHP identifier characters and exists on the handler object:

```php
public function dispatch(object $handler, string $method, array $params): void
{
    // Validate method name contains only valid PHP identifier characters
    if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $method)) {
        throw new \RuntimeException("Invalid method name: $method");
    }

    // Verify the method exists on the handler object
    if (!method_exists($handler, $method)) {
        throw new \RuntimeException("Method does not exist on handler: $method");
    }

    $handler->$method($params);
}
```

Alternatively, validate in ActionResolver before returning the method name to enforce the constraint at the source of the split.

## Explanation
The dynamic method invocation `$handler->$method()` treats the method name as an executable "command" on the object. Without validation, an attacker can submit crafted action strings (e.g., `"email.__construct"`, `"email.__call"`, or method names targeting unintended methods on the handler) to invoke methods not intended to be callable through the workflow API.

The fix implements input validation using a regex allowlist that restricts the method name to valid PHP identifiers (starting with a letter or underscore, followed by letters, digits, or underscores). The `method_exists()` call provides defense-in-depth by confirming the method is actually present and callable on the handler object, preventing both typo-based bypasses and attempts to invoke non-existent or private methods. This satisfies CWE-77 by neutralizing the "command" portion of the injection through validation at the point of use.
