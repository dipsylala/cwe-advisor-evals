## Verdict

Confirmed exploitable. Untrusted tenant-supplied JavaScript flows directly to `ScriptEngine.eval()` with no validation or filtering. An account administrator can inject arbitrary code that executes within the application's runtime with full access to the engine context.

## Source

**Parameter:** `ruleSource` in `CustomValidationRuleService.evaluateCustomRule()` (line 32)
- Documented as untrusted ("tenant-authored JavaScript rule body, untrusted")
- Passes through with no transformation (line 25 comment confirms "no transformation")

## Fix

Replace dynamic code evaluation with a strategy pattern dispatch table mapping rule identifiers to predefined safe validators. Remove `javax.script.ScriptEngine` imports and all `eval()` calls.

**Fixed code:**

```java
package com.example.rules;

import java.util.HashMap;
import java.util.Map;

/**
 * Lets an account administrator select from a set of predefined validation rules
 * that run against each incoming order before it is accepted. Rules are identified
 * by a well-known string key; arbitrary code execution is not permitted.
 */
public class CustomValidationRuleService {

    @FunctionalInterface
    private interface ValidationRule {
        boolean evaluate(double orderTotal, String customerTier);
    }

    private static final Map<String, ValidationRule> RULE_REGISTRY = new HashMap<>();

    static {
        // Predefined safe validation rules; add more as needed
        RULE_REGISTRY.put("min_order_100", (orderTotal, customerTier) -> orderTotal >= 100.0);
        RULE_REGISTRY.put("min_order_500", (orderTotal, customerTier) -> orderTotal >= 500.0);
        RULE_REGISTRY.put("premium_tier_only", (orderTotal, customerTier) -> "PREMIUM".equals(customerTier));
        RULE_REGISTRY.put("standard_or_premium", (orderTotal, customerTier) -> 
            "STANDARD".equals(customerTier) || "PREMIUM".equals(customerTier));
    }

    /**
     * Evaluates a named custom validation rule against the order under review.
     * ruleSource must match a key in the predefined rule registry; arbitrary
     * code execution is not permitted.
     *
     * @param ruleSource   the name of a predefined validation rule
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     * @throws IllegalArgumentException if ruleSource does not match a registered rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) 
            throws IllegalArgumentException {
        
        if (ruleSource == null || ruleSource.trim().isEmpty()) {
            throw new IllegalArgumentException("Rule name cannot be null or empty");
        }

        String ruleName = ruleSource.trim();
        ValidationRule rule = RULE_REGISTRY.get(ruleName);
        
        if (rule == null) {
            throw new IllegalArgumentException("Unknown validation rule: " + ruleName);
        }

        return rule.evaluate(orderTotal, customerTier);
    }
}
```

## Explanation

The fix replaces `ScriptEngine.eval()` with a dispatch table (`RULE_REGISTRY`) of predefined, type-safe validator functions. Admins now select a rule by its well-known identifier (e.g., `"min_order_500"`) rather than supplying arbitrary JavaScript code. Each validator encapsulates a specific business rule and performs only the intended validation logic.

The attack surface is eliminated because:
1. The input (`ruleSource`) is no longer evaluated as code; it is treated only as a string key
2. Only rules explicitly registered in `RULE_REGISTRY` can execute
3. Each rule is a Java lambda with no reflection, type loading, or system access beyond the parameters it receives
4. Attempts to register new rules or modify the registry require code changes and recompilation, not runtime configuration

The method signature remains compatible: it still accepts the same parameters and returns a boolean. Exception behavior changes from `ScriptException` to `IllegalArgumentException` when the rule is unknown (a safer, more predictable contract).

## Behaviour changes

**For valid rule names:** Behavior is identical to before for any rule that was previously supplied. If the admin console previously accepted `"min_order_100"` as a rule, it now dispatches to the predefined lambda. If it accepted arbitrary JavaScript, admins must switch to rule identifiers.

**For invalid or missing rules:** Now throws `IllegalArgumentException` instead of `ScriptException`, and with a clear message naming the unknown rule. This is a breaking change if code relied on catching `ScriptException` specifically, but the new exception type is more semantic and allows calling code to distinguish "rule not found" (configuration error) from "rule syntax error" (would never occur here).

**Configuration impact:** The admin console must be updated to provide a dropdown or autocomplete of valid rule names instead of a free-text JavaScript editor. This is necessary to close the injection vector and is a trade-off for safety - arbitrary custom expressions are no longer supported. New business rules require a code change and redeployment.

**Performance:** Dispatching to a registered lambda is faster than parsing and interpreting JavaScript on every invocation.
