## Verdict

CONFIRMED. CWE-77 (Improper Neutralization of Special Elements used in a Command ('Command Injection')) is present. The `$method` parameter passed to `ActionDispatcher::dispatch()` originates from untrusted user input (the portion of the action string after the dot) without validation of method existence or whitelist enforcement. An attacker can invoke arbitrary methods on the handler object, including magic methods like `__construct`, `__destruct`, `__call`, or `__get`, bypassing intended workflow actions.

## Source

Data flow from user input to vulnerable sink:

1. **Entry point** (WorkflowStepController.php:16): `file_get_contents('php://input')` reads untrusted JSON from the request body.
2. **Propagation** (WorkflowStepController.php:29): The `action` field is passed to `WorkflowStep` constructor without validation of method names.
3. **Partial validation** (ActionResolver.php:36-45): The action string is split on `.` and the category (first part) is validated against a registry. However, the method name (second part) is extracted without any check that it exists, is public, or is safe to invoke.
4. **Vulnerable sink** (ActionDispatcher.php:12): `$handler->$method($params)` performs dynamic method invocation using the user-controlled `$method` value.

An attacker can craft an action like `"email.__construct"` to invoke magic methods, or `"email.nonExistentMethod"` to trigger `__call`, leading to unintended behavior or information disclosure.

## Fix

Validate the method exists and is intended to be called before invoking it. Use one of these approaches:

**Option A: Whitelist public methods per handler**
Maintain an explicit list of allowed methods for each handler class, and validate against it in `ActionResolver::resolve()` before returning the method name. Check `in_array($method, $allowedMethods)` and throw an exception if the method is not in the list.

**Option B: Reflect to validate method existence**
In `ActionDispatcher::dispatch()`, before executing the dynamic call, use PHP reflection to verify the method exists and is public:
```php
$reflection = new ReflectionClass($handler);
if (!$reflection->hasMethod($method) || !$reflection->getMethod($method)->isPublic()) {
    throw new RuntimeException("Method not found or not public: $method");
}
```
Then check that the method is not a magic method (name does not start with `__`).

**Option C: Immutable handler method registry**
Modify each handler class to expose a static list of allowed public methods it accepts. Pass this list to `ActionResolver` at construction, and validate the resolved method against it.

For this codebase, **Option B** (reflection validation) is minimal and effective. Add a check immediately before the dynamic call to ensure:
1. The method exists on the handler object.
2. The method is public (not protected or private).
3. The method name does not start with `__` (excluding magic methods from dynamic invocation).

## Explanation

CWE-77 encompasses improper neutralization of special characters in command-like contexts. In this case, PHP's dynamic method invocation (`$object->$method()`) acts as the "command" and the method name is the attacker-controlled element.

The vulnerability exists because:

1. **No allowlist or validation of method names**: The `ActionResolver` validates the category (first part of the action) against a registry but passes the method name (second part) through untrusted.
2. **Dynamic method calls without guards**: `$handler->$method($params)` will invoke any callable method on the object, including inherited methods and magic methods.
3. **Attack surface includes magic methods**: An attacker can call `__construct` to reinitialize the handler, `__call` to trigger undefined method handling, or other magic methods depending on what the handler implements.

The fix enforces that only explicitly defined public methods can be invoked, preventing attackers from calling unintended or dangerous methods. This aligns with the principle of least privilege: the dispatcher should only call methods the handler author intended for external invocation.
