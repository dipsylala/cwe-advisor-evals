## Verdict

Exploitable. CWE-94, Improper Control of Generation of Code ('Code Injection'). The file's own documentation states the target runtime is JDK 11, where Nashorn still ships in the JDK and `ScriptEngineManager().getEngineByName("JavaScript")` resolves to a live engine, so the `eval()` call at line 42 is a genuine, reachable sink rather than dead code.

## Source

`ruleSource`, the first parameter of `evaluateCustomRule(String ruleSource, double orderTotal, String customerTier)`. It is tenant/admin-authored free-text JavaScript, typed into the "custom validation rule" field of the admin console and stored with the account configuration, then passed to this method with no transformation, validation, or allowlisting anywhere in the call chain (the case directory contains only this one file).

Sink: `engine.eval(ruleSource)` (`javax.script.ScriptEngine.eval(String)`) at line 42, where `engine` is obtained from `ScriptEngineManager.getEngineByName("JavaScript")` (Nashorn). Nashorn gives an evaluated script full access to the JVM - `java.lang.Runtime`, reflection, the file system, and the network - with no execution timeout or memory bound, so an attacker who controls the rule text controls code execution inside the application process.

## Fix

### File: CustomValidationRuleService.java

```java
package com.example.rules;

import java.io.ByteArrayOutputStream;

import javax.script.ScriptException;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.HostAccess;
import org.graalvm.polyglot.PolyglotException;
import org.graalvm.polyglot.ResourceLimits;
import org.graalvm.polyglot.SandboxPolicy;
import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.io.IOAccess;

/**
 * Lets an account administrator define a "custom validation rule" that runs
 * against each incoming order before it is accepted. The rule body is stored
 * as free-text JavaScript and supplied per-request from the admin console.
 *
 * The rule is evaluated with GraalVM's polyglot JavaScript engine under
 * SandboxPolicy.CONSTRAINED: host classes and objects are unreachable
 * (HostAccess.NONE, host class lookup denied), file/socket IO is denied
 * (IOAccess.NONE), and native access, process creation and JVM exit are
 * denied by the policy itself. A statement-count resource limit bounds
 * runaway scripts (an infinite loop) so a hostile or buggy rule cannot hold
 * a request thread indefinitely.
 */
public class CustomValidationRuleService {

    // Guest-language statements a single rule may execute before its context
    // is cancelled and closed; bounds worst-case CPU use per evaluation.
    private static final long RULE_STATEMENT_LIMIT = 10_000;

    /**
     * Evaluates the tenant-supplied validation rule against the order under
     * review. ruleSource is the raw text the admin typed into the "custom
     * validation rule" field and saved with the account configuration; it is
     * passed straight through to the request handler with no transformation,
     * and now runs inside a sandboxed, per-call GraalVM context rather than
     * a fully-privileged JDK script engine.
     *
     * @param ruleSource   tenant-authored JavaScript rule body, untrusted
     * @param orderTotal   order total in minor currency units
     * @param customerTier loyalty tier of the customer placing the order
     * @return true if the order passes the custom rule
     */
    public boolean evaluateCustomRule(String ruleSource, double orderTotal, String customerTier) throws ScriptException {
        Context context;
        try {
            context = Context.newBuilder("js")
                    .sandbox(SandboxPolicy.CONSTRAINED)
                    .allowHostAccess(HostAccess.NONE)
                    .allowHostClassLookup(className -> false)
                    .allowIO(IOAccess.NONE)
                    .allowCreateThread(false)
                    .resourceLimits(ResourceLimits.newBuilder()
                            .statementLimit(RULE_STATEMENT_LIMIT, null)
                            .build())
                    .out(new ByteArrayOutputStream())
                    .err(new ByteArrayOutputStream())
                    .build();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("JavaScript engine not available on this runtime", e);
        }

        try (context) {
            context.getBindings("js").putMember("orderTotal", orderTotal);
            context.getBindings("js").putMember("customerTier", customerTier);

            Value result = context.eval("js", ruleSource);
            return result.isBoolean() && result.asBoolean();
        } catch (PolyglotException e) {
            throw new ScriptException("Custom validation rule failed to evaluate: " + e.getMessage());
        }
    }
}
```

## Explanation

The original code handed tenant-controlled JavaScript straight to Nashorn's `ScriptEngine.eval()`, which executes with full, unrestricted access to the JVM and no resource bound - the textbook CWE-94 outcome, where anyone who can set the "custom validation rule" field gets code execution inside the application process. The fix keeps the feature and the rule language (JavaScript) - switching to a different expression language such as JEXL would silently invalidate every already-stored admin rule, since none of them were written against JEXL's grammar - but replaces the engine with GraalVM's polyglot `Context` for `"js"`, built under `SandboxPolicy.CONSTRAINED` with `HostAccess.NONE` and host class lookup denied so the script cannot name or reach any Java class, object, or reflective surface; `IOAccess.NONE` plus the policy's own denial of native access, process creation, and JVM exit close the file, socket, subprocess, and shutdown paths; and a `ResourceLimits` statement-count cap bounds worst-case CPU time so a hostile or accidentally infinite rule (`while(true){}`) can no longer hold a request thread indefinitely. This closes the weakness by restricting what the engine can reach rather than by filtering the script text, per the loaded guidance's rule that a denylist on the input string is not a fix. `CONSTRAINED` still shares a heap and OS process with the host JVM, so it is a strong best-effort boundary rather than the out-of-process isolation the guidance recommends for a fully adversarial actor; if the admin population for this feature should be treated as potentially hostile rather than merely fallible, run the evaluation in a separate process or container with OS-level resource limits in front of this code, as an additional layer. The fixed file was compiled clean (`javac`, no errors or warnings) against the real `org.graalvm.polyglot:polyglot:25.0.3` jar, confirming every new class, method, and constant used (`Context.Builder.sandbox/allowHostAccess/allowHostClassLookup/allowIO/allowCreateThread/resourceLimits/out/err`, `SandboxPolicy.CONSTRAINED`, `HostAccess.NONE`, `IOAccess.NONE`, `ResourceLimits.newBuilder().statementLimit(long, Predicate)`, `Context.getBindings`, `Value.putMember/isBoolean/asBoolean`, `PolyglotException`) exists with the signature used.

## Behaviour changes

- The `ScriptEngineManager` field and Nashorn engine lookup are gone; a fresh sandboxed `Context` is built per call instead. Direct consequence of the fix - Nashorn has no host-access boundary this feature needs.
- A missing engine now surfaces as `IllegalStateException("JavaScript engine not available on this runtime", cause)`, mapped from `IllegalArgumentException` thrown by `Context.newBuilder("js").build()` when the GraalVM JS component isn't on the runtime classpath. This preserves the original method's fail-fast exception type and message for that case.
- Script-evaluation failures still surface as the checked `ScriptException` the method already declared, now wrapping GraalVM's `PolyglotException` message instead of Nashorn's native error text, so existing callers that catch `ScriptException` keep compiling and keep the same error-handling shape.
- Added `RULE_STATEMENT_LIMIT` (10,000 guest-language statements) as a new resource bound with no prior equivalent - this is a defense-in-depth starting value, not sourced from the loaded guidance or a vendor default, and should be tuned to the real complexity of validation rules in production before relying on it.
- `SandboxPolicy.CONSTRAINED` requires the guest's stdout/stderr to be redirected rather than inherited; both are now discarded into a `ByteArrayOutputStream`. The original ScriptEngine path never captured or returned script output either, so no output the caller previously received is now dropped.
- The result mapping changes from `Object` plus `Boolean.TRUE.equals(result)` to `Value` plus `result.isBoolean() && result.asBoolean()` - same semantics: the order passes only when the rule's result is exactly JavaScript `true`.
- The class and method Javadoc were updated to describe the new engine and its sandboxing; no functional effect.
