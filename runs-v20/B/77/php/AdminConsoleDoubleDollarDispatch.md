## Verdict

Not exploitable. CWE-77 (command injection via attacker-controlled dynamic dispatch) does not hold for this code as written. Confidence: high (positively reproduced against PHP 8.5.8 CLI, not inferred from documentation alone).

## Source

- Source: `$_POST['action']`, read into `$cmd = trim($_POST['action'] ?? '')` (`AdminConsoleDoubleDollarDispatch.php:14`).
- Reported sink: `$$cmd()` at `AdminConsoleDoubleDollarDispatch.php:20`.
- Call chain: single file, single function - `handleAdminConsoleCommand()` reads `$_POST['action']`, trims it, and immediately dispatches on it. No intermediate functions.

`$$cmd()` is a genuine CWE-77 taint sink in general (the local knowledge base lists it explicitly alongside `call_user_func()` and `$obj->$method()`), and a careless read of this line - "variable content picks the function to call" - matches that pattern. The trace below shows why this specific instance does not.

`$$cmd()` parses as `${$cmd}()`: PHP first resolves `${$cmd}` - the value of the *variable* whose name equals the string in `$cmd` - and then invokes whatever that variable holds. This is variable-variable indirection into the local symbol table, not a variable-function call by name (that would be the single-dollar form `$cmd()`, which calls the function literally named by `$cmd`'s value). The two are frequently conflated, and the difference is the entire finding here: `$cmd()` would call `clearCache()` for input `"clearCache"`; `$$cmd()` does not.

At the point `$$cmd()` executes, the only variable in `handleAdminConsoleCommand()`'s local scope is `$cmd` itself. I reproduced this against PHP 8.5.8 (CLI) with the exact code shape (same statement order, same `$_POST['action']` read, same `trim`, same `$$cmd()` call):

- Input `"clearCache"` (or `"purgeSessions"`, or any function name): PHP looks for a local variable named `clearCache` - none exists - emits `Warning: Undefined variable $clearCache`, then `Fatal error: Uncaught Error: Value of type null is not callable`. The intended handlers are never reached even for their own, legitimate command words.
- Input `"_POST"`, `"GLOBALS"`, or any other superglobal name: still `Warning: Undefined variable $_POST` / `$GLOBALS`, then the same "null is not callable" fatal error. Superglobals are not resolvable through dynamic (`${$name}`) variable-variable lookup the way they are through their literal token form, even when `$_POST` was already read by its literal name two lines earlier in the same function - confirmed empirically, not assumed.
- Input `"cmd"` (the one string that matches an actual local variable name): `${$cmd}` resolves to `$cmd`'s own value, i.e. the string `"cmd"` again. PHP then attempts to invoke the string `"cmd"` as a function name and throws `Fatal error: Uncaught Error: Call to undefined function cmd()`.

So for every possible value of `$_POST['action']`, `$$cmd()` either throws immediately (most inputs) or self-resolves back to the fixed, non-existent function name `"cmd"` (only when the input is literally `"cmd"`). There is no value an attacker can submit that causes `${$cmd}` to evaluate to anything other than `null` or the constant string `"cmd"`. The attacker's content never becomes the thing that gets called - only the fixed literal `"cmd"` ever does, and that function doesn't exist. This breaks the CWE-77 precondition that untrusted input controls which command/function executes: here it controls nothing except whether the request crashes.

## Fix

No fix proposed. Per the skill's Step 4 guidance, a confirmed-broken data-flow path is reported rather than patched, and no file was changed.

The underlying application bug is real but is a correctness defect, not a security one: because the code uses `$$cmd()` instead of the (single-dollar) variable-function form `$cmd()`, the admin console cannot invoke `clearCache()` or `purgeSessions()` for any input at all - it fails closed with a fatal error in every case. If this handler is fixed for functionality, the fix should not be "change `$$cmd()` to `$cmd()`" in isolation, since that would convert today's inert construct into a genuinely exploitable variable-function call (arbitrary function-name dispatch on unvalidated input). Any future functional fix must pair the switch to `$cmd()`-style (or `call_user_func()`-style) dispatch with the allowlist pattern in `cwe/77/php/INDEX.md`: map recognized verbs (`clearCache`, `purgeSessions`) in a fixed associative array to their handler references, look up the trimmed input in that array, reject anything not found, and invoke only the looked-up handler reference - never the original request string.

## Explanation

The line flagged by the scanner performs variable-variable indirection (`${$cmd}()`), not variable-function dispatch (`$cmd()`); the two look similar but resolve differently, and only the latter lets a string value select an arbitrary function by name. Reproducing the exact code shape on PHP 8.5.8 shows `${$cmd}` can only ever evaluate to `null` (for any input other than the literal string `"cmd"`) or to the fixed string `"cmd"` (when the input is exactly `"cmd"`), because the only local variable in scope is `$cmd` and superglobals are not reachable through this dynamic form. In both cases PHP throws before any attacker-influenced function name is invoked, so no assumption, validation gap, or missing check needs to be added - the sink cannot be steered by input as it stands. No code was changed.

## Behaviour changes

None - no file was modified.
