## Verdict

**Exploitable.** The `ruleSource` parameter accepts untrusted JavaScript code text from the admin console and passes it directly to `ScriptEngine.eval()`. There is no isolation, sandbox, or validation. An attacker with admin access can inject arbitrary code that executes with full access to the engine's bindings (orderTotal, customerTier variables), the application's classpath, and any credentials or secrets accessible to the runtime.

## Source

```java
// File: CustomValidationRuleService.java, lines 32-42
public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
    ScriptEngine engine = engineManager.getEngineByName("JavaScript");
    if (engine == null) {
        throw new IllegalStateException("JavaScript engine not available on this runtime");
    }

    engine.put("orderTotal", orderTotal);
    engine.put("customerTier", customerTier);

    // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    Object result = engine.eval(ruleSource);  // VULNERABLE: ruleSource is untrusted

    return Boolean.TRUE.equals(result);
}
```

**Data flow**: `ruleSource` (untrusted admin input) → `engine.eval(ruleSource)` (code execution sink)

## Fix

Replace dynamic script evaluation with a predefined rule strategy pattern. Store validation logic as named, pre-written Java methods instead of accepting arbitrary JavaScript source:

```java
package com.example.rules;

import java.util.EnumMap;
import java.util.Map;

/**
 * Validation rules are now predefined and named, rather than dynamically
 * evaluated from untrusted JavaScript source. Administrators select a rule
 * by name; the rule body is fixed Java code, not user-supplied text.
 */
public enum ValidationRule {
    TIER_BASED_DISCOUNT {
        @Override
        public boolean validate(double orderTotal, String customerTier) {
            // Tier-based discount: gold customers get 10% discount threshold
            double threshold = "gold".equals(customerTier) ? orderTotal * 0.9 : orderTotal;
            return threshold > 0;
        }
    },
    MINIMUM_ORDER {
        @Override
        public boolean validate(double orderTotal, String customerTier) {
            // Minimum order: $1000 for standard, $500 for gold
            double minimum = "gold".equals(customerTier) ? 50000 : 100000; // in minor currency units
            return orderTotal >= minimum;
        }
    },
    ALWAYS_ACCEPT {
        @Override
        public boolean validate(double orderTotal, String customerTier) {
            return true;
        }
    };

    public abstract boolean validate(double orderTotal, String customerTier);
}

public class CustomValidationRuleService {

    private final Map<String, ValidationRule> ruleRegistry = new EnumMap<>(ValidationRule.class);

    public CustomValidationRuleService() {
        // Populate registry: map rule identifiers to predefined implementations
        for (ValidationRule rule : ValidationRule.values()) {
            ruleRegistry.put(rule.name(), rule);
        }
    }

    /**
     * Evaluates a named validation rule against the order under review.
     * ruleName is the identifier for a predefined rule; no code execution occurs.
     *
     * @param ruleName     name of a predefined validation rule (administrator selects from a dropdown)
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the selected rule
     * @throws IllegalArgumentException if ruleName does not match a known rule
     */
    public boolean evaluateCustomRule(String ruleName, double orderTotal, String customerTier) {
        // Validate and look up the rule by name
        ValidationRule rule = ruleRegistry.get(ruleName);
        if (rule == null) {
            throw new IllegalArgumentException("Unknown validation rule: " + ruleName);
        }

        // Execute the predefined rule logic (no dynamic code evaluation)
        return rule.validate(orderTotal, customerTier);
    }
}
```

## Explanation

The fix eliminates CWE-94 by removing the `ScriptEngine.eval()` call entirely. Instead of accepting untrusted JavaScript source text, the service now:

1. **Defines rules as Java code**, not user-supplied text. Each rule is a method in the `ValidationRule` enum, written by developers, reviewed in code review, and deployed with the application.

2. **Accepts a rule name**, not source. The administrator selects a rule from a predefined list (e.g., a dropdown menu in the admin console) rather than typing JavaScript code.

3. **Uses a lookup table** (`ruleRegistry`) to map rule names to rule implementations. The attacker surface is eliminated: there is no code injection point, because no untrusted text is evaluated.

4. **Preserves the contract**: The method still returns a boolean indicating pass/fail, still validates against `orderTotal` and `customerTier`, and still supports multiple rule types. The admin can still "customize" validation by selecting from available rules; the customization is now constrained to safe options.

The Java-specific guidance states: "Remove or disable `ScriptEngine` access to untrusted input entirely - there is no safe way to sandbox Nashorn/Rhino for arbitrary user expressions" and "Replace dynamic script evaluation with predefined logic: switch statements, strategy patterns, or configuration-driven dispatch tables." This fix follows both prescriptions.

## Behaviour changes

- **Administrator experience**: Instead of pasting JavaScript code, admins now select a rule name (e.g., "TIER_BASED_DISCOUNT") from a dropdown or enumeration of available rules. The set of rules is fixed at deployment time.
- **Rule authorship**: New rules can no longer be added at runtime through the admin console. They must be coded by developers, merged, built, and deployed—the same as other application logic.
- **Error handling**: Invalid rule names now throw `IllegalArgumentException` instead of `ScriptException`. Existing error handling for rule validation failures is no longer needed (rules cannot throw exceptions during execution; they return true/false).
- **Performance**: No runtime script engine initialization or compilation. Each call is a direct Java method invocation.
- **Auditability**: Rule changes are now code changes, captured in version control and code review, rather than admin console edits.
