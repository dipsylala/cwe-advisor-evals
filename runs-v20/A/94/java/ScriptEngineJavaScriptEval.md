## Verdict

Confirmed. `evaluateCustomRule` passes tenant-authored, request-supplied text (`ruleSource`) straight into `ScriptEngine.eval()` on a full Nashorn JavaScript engine. Nashorn's Java-object bridge lets any script reach arbitrary JVM classes (e.g. `Java.type("java.lang.Runtime").getRuntime().exec(...)`, `Java.type("java.lang.ProcessBuilder")`, file and network I/O), so this is full arbitrary code execution in the process, not a sandboxed expression evaluator.

## Source

`ruleSource` in `CustomValidationRuleService.evaluateCustomRule(String ruleSource, double orderTotal, String customerTier)` - per the class Javadoc, the raw text an account administrator/tenant typed into the "custom validation rule" field, saved with account configuration, and "passed straight through to the request handler with no transformation." It reaches the sink at line 42 (`engine.eval(ruleSource)`) with no validation, allowlisting, or sandboxing applied anywhere on the path.

## Fix

### File: CustomValidationRuleService.java

```java
package com.example.rules;

import javax.script.ScriptEngine;
import javax.script.ScriptException;

import jdk.nashorn.api.scripting.ClassFilter;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;

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

    private final NashornScriptEngineFactory engineFactory = new NashornScriptEngineFactory();

    // Denies every Java class to the script. Combined with the "--no-java"
    // engine flag below this removes Nashorn's Java-object bridge (Java.type,
    // Packages, and the java/javax/com/edu/org/javafx globals), which is how
    // an eval'd script would otherwise reach java.lang.Runtime,
    // ProcessBuilder, file I/O, or reflection.
    private static final ClassFilter DENY_ALL_JAVA_CLASSES = className -> false;

    // Neutralizes the handful of Nashorn built-ins that are native to the
    // engine rather than part of the Java bridge, so "--no-java" and the
    // ClassFilter above do not cover them: load()/loadWithNewGlobal() can
    // fetch and execute a second script from a file or URL, readFully()/
    // readLine() can read local files or stdin, and exit()/quit() can
    // terminate the JVM. Overwriting them before the tenant rule ever runs
    // removes those globals from the scope the rule executes in.
    private static final String LOCKDOWN_SCRIPT =
            "load = function() { throw new Error('load is disabled'); };"
                    + "loadWithNewGlobal = function() { throw new Error('loadWithNewGlobal is disabled'); };"
                    + "readFully = function() { throw new Error('readFully is disabled'); };"
                    + "readLine = function() { throw new Error('readLine is disabled'); };"
                    + "exit = function() { throw new Error('exit is disabled'); };"
                    + "quit = function() { throw new Error('quit is disabled'); };";

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
        ScriptEngine engine = engineFactory.getScriptEngine(
                new String[] {"--no-java", "--no-syntax-extensions"},
                getClass().getClassLoader(),
                DENY_ALL_JAVA_CLASSES);
        if (engine == null) {
            throw new IllegalStateException("JavaScript engine not available on this runtime");
        }

        engine.eval(LOCKDOWN_SCRIPT);

        engine.put("orderTotal", orderTotal);
        engine.put("customerTier", customerTier);

        Object result = engine.eval(ruleSource);

        return Boolean.TRUE.equals(result);
    }
}
```

## Explanation

The original code obtained Nashorn through the generic `ScriptEngineManager().getEngineByName("JavaScript")` and called `eval()` on it with no restriction, so the tenant-authored rule body ran with the same privileges as the host application and full access to Nashorn's Java-object bridge - the rule could execute `Java.type("java.lang.Runtime").getRuntime().exec("...")`, instantiate `ProcessBuilder`, read/write arbitrary files, or open sockets, entirely outside anything the "order validation" feature needs.

The fix confines the untrusted script to the small ECMAScript surface the feature actually requires instead of trying to filter or transform the script text:

- It builds the engine via `NashornScriptEngineFactory.getScriptEngine(String[] args, ClassLoader appLoader, ClassFilter classFilter)` rather than `ScriptEngineManager`, because that overload is the supported extension point for constraining a Nashorn instance.
- `--no-java` removes the `Java` global object and the `java`/`javax`/`com`/`edu`/`org`/`javafx` package globals, closing the primary route to arbitrary JVM classes. `--no-syntax-extensions` removes Nashorn-specific syntax sugar the rule body has no legitimate need for.
- The `ClassFilter` that returns `false` for every class name is defense-in-depth for the same bridge, in case any Java-class exposure remains reachable through another path.
- `load()`, `loadWithNewGlobal()`, `readFully()`, `readLine()`, `exit()`, and `quit()` are native Nashorn globals, not part of the Java bridge, so `--no-java` and the `ClassFilter` do not touch them; each is still capable of file/network access or terminating the JVM. The lockdown script overwrites all six with functions that immediately throw, and it runs before `orderTotal`/`customerTier` are bound and before the tenant rule is evaluated, so the rule never observes the original implementations.

With these in place, `ruleSource` can only perform plain JavaScript logic over the two bound values, which is exactly what a "custom validation rule" is supposed to do. One residual risk this does not address is availability: a rule containing an infinite loop or heavy computation can still tie up the evaluating thread, since none of the above bounds execution time. That is a resource-exhaustion concern (CWE-400), separate from the code-injection finding here, and would need a timeout enforced by running `eval` on a bounded/interruptible thread if tenant rules must run unattended.
