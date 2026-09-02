package com.example.rules;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * Lets an account administrator define a "custom validation rule" that runs
 * against each incoming order before it is accepted. The rule body is stored
 * as free-text JavaScript and supplied per-request from the admin console.
 *
 * Targets JDK 11, where the Nashorn engine still ships in the JDK itself
 * (deprecated by JEP 335 but not yet removed; removal followed in JDK 15 per
 * JEP 372), so ScriptEngineManager().getEngineByName("JavaScript") resolves
 * to a live engine and this eval() call is a genuine, reachable sink.
 */
public class CustomValidationRuleService {

    private final ScriptEngineManager engineManager = new ScriptEngineManager();

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration; it is
     * passed straight through to the request handler with no transformation.
     *
     * @param ruleSource   tenant-authored JavaScript rule body, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
        ScriptEngine engine = engineManager.getEngineByName("JavaScript");
        if (engine == null) {
            throw new IllegalStateException("JavaScript engine not available on this runtime");
        }

        engine.put("orderTotal", orderTotal);
        engine.put("customerTier", customerTier);

        // SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
        Object result = engine.eval(ruleSource);

        return Boolean.TRUE.equals(result);
    }
}
