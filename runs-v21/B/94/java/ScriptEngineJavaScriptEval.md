## Verdict

Exploitable. The `ruleSource` parameter is explicitly documented as tenant-authored and untrusted (line 27). It is passed directly to `engine.eval(ruleSource)` at line 42 without any validation, sanitization, or transformation. A tenant can supply arbitrary JavaScript code that executes with full access to variables and objects in the engine's scope, including `orderTotal` and `customerTier`, as well as potentially accessing the engine's host bindings and internals.

## Source

**Line 27-28 (parameter documentation)**: `@param ruleSource   tenant-authored JavaScript rule body, untrusted`

**Line 32 (method signature)**: `public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException`

The `ruleSource` parameter is the entry point. It originates from account configuration stored by an administrator and is passed through to the request handler without transformation (as documented in the javadoc).

## Fix

### File: CustomValidationRuleService.java

```java
package com.example.rules;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Lets an account administrator select a "custom validation rule" from a set of
 * predefined rules that run against each incoming order before it is accepted.
 * The rule identifier is stored as configuration and supplied per-request from
 * the admin console, preventing code injection.
 *
 * Targets JDK 11+. Rules are defined as Java functions in a lookup map rather
 * than evaluated from untrusted JavaScript, eliminating code injection risk.
 */
public class CustomValidationRuleService {

    private final Map<String, BiFunction<Double, String, Boolean>> rules = new HashMap<>();

    public CustomValidationRuleService() {
        // Define safe, predefined validation rules
        rules.put("premium_tier_discount", (orderTotal, customerTier) ->
            "premium".equals(customerTier) && orderTotal > 1000.0);
        rules.put("high_value_order", (orderTotal, customerTier) ->
            orderTotal > 5000.0);
        rules.put("gold_member", (orderTotal, customerTier) ->
            "gold".equals(customerTier));
    }

    /**
     * Evaluates a named validation rule against the order under review.
     * ruleIdentifier identifies a predefined rule, preventing code injection.
     *
     * @param ruleIdentifier   identifier of a predefined validation rule
     * @param orderTotal       order total in minor currency units
     * @param customerTier     loyalty tier of the customer placing the order
     * @return true if the order passes the selected rule
     * @throws IllegalArgumentException if the rule identifier is not recognized
     */
    public boolean evaluateCustomRule(String ruleIdentifier, double orderTotal, String customerTier) {
        BiFunction<Double, String, Boolean> rule = rules.get(ruleIdentifier);
        if (rule == null) {
            throw new IllegalArgumentException("Unknown rule identifier: " + ruleIdentifier);
        }
        return rule.apply(orderTotal, customerTier);
    }
}
```

## Explanation

The fix eliminates the code injection vulnerability by removing `ScriptEngine.eval()` entirely. The original code evaluated arbitrary JavaScript supplied by a tenant, which the Java CWE-94 guidance explicitly forbids: "there is no safe way to sandbox Nashorn/Rhino for arbitrary user expressions." 

The replacement uses a lookup table pattern (recommended in the guidance as the primary defence): validation rules are now defined as predefined Java `BiFunction` lambdas in a `HashMap`. Instead of accepting arbitrary JavaScript source code, the method accepts a `ruleIdentifier` string that names a predefined rule. The identifier is looked up in the map, and the corresponding Java function is invoked to perform the validation. This approach eliminates the attack surface entirely: an attacker cannot inject code because no code is evaluated from untrusted input. The set of rules is fixed and controlled by the application, not by user input.

The method now throws `IllegalArgumentException` if an unrecognized rule identifier is supplied, providing clear failure semantics instead of the undefined behaviour of eval failures.

## Behaviour changes

1. **Method signature changed**: The first parameter changed from `ruleSource` (arbitrary JavaScript source) to `ruleIdentifier` (a string naming a predefined rule). This is a necessary change to close the vulnerability, as the ability to evaluate arbitrary untrusted code must be removed entirely. Callers must change from passing JavaScript code to passing the name of a rule (e.g., `"premium_tier_discount"` instead of JavaScript source like `"customerTier === 'premium' && orderTotal > 1000"`).

2. **Exception type changed**: The method now throws `IllegalArgumentException` instead of `ScriptException` when a rule lookup fails. This provides clearer failure semantics and a more type-safe exception that callers can distinguish from other errors.

3. **No ambient engine state**: The original code populated the engine's scope with `engine.put("orderTotal", ...)` and `engine.put("customerTier", ...)`. The fixed code passes these directly as parameters to the rule function, requiring no engine state setup. This is a cleaner design.

4. **Public constructor added**: The fixed class now has an explicit public no-argument constructor that populates the rules map. The original had an implicit constructor. A caller instantiating the class will trigger this setup automatically on construction.

The method still returns a boolean as before, matching the original contract. The change is intentional and necessary: accepting arbitrary JavaScript is the vulnerability, and that capability cannot be preserved while remaining safe. The fixed code was compiled successfully with `javac` on JDK 11+ without errors, using only JDK standard library classes (`java.util.HashMap`, `java.util.Map`, `java.util.function.BiFunction`), requiring no external dependencies.
