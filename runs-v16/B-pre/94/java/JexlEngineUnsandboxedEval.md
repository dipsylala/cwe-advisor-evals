## Verdict

**Exploitable** (high confidence).

**Location**: evals/cases/94/java/JexlEngineUnsandboxedEval/ReportFilterService.java, line 38 (sink). The JexlEngine is instantiated unsandboxed at line 25.

## Source

The analyst-supplied filter expression is the untrusted input. It originates as a string submitted through the "Edit Filter" form, persisted without validation, and passed to `applyFilter()` as the `filterExpression` parameter (line 36). The application description explicitly states these are "user-authored filter expressions."

## Fix

**Vulnerable code** (lines 22–26):

```java
public ReportFilterService() {
    // No JexlSandbox is configured, so the engine has full, unrestricted
    // access to every class and method reachable from the context.
    this.jexlEngine = new JexlBuilder().create();
}
```

**Fixed code**:

```java
public ReportFilterService() {
    // Create a deny-by-default sandbox to restrict what expressions can access.
    // Only simple property access on context variables is allowed; no method invocation
    // on unexpected classes or object instantiation.
    JexlSandbox sandbox = new JexlSandbox(false);
    this.jexlEngine = new JexlBuilder().sandbox(sandbox).create();
}
```

**Import to add** (if not already present):

```java
import org.apache.commons.jexl3.JexlSandbox;
```

## Explanation

The original code instantiates a JEXL engine without sandbox restrictions. An analyst can supply a filter expression containing arbitrary code—for example, `Runtime.getRuntime().exec("command")` or class instantiation—and the engine will execute it with full access to Java reflection and the classpath. The fixed code creates a deny-by-default sandbox using `new JexlSandbox(false)`. This sandbox prevents access to Java methods and class instantiation by default, allowing only property access on objects provided via the evaluation context (the `amount`, `region`, `owner`, and `row` variables set at lines 47–50). Attackers can no longer use reflection or method invocation to escape the sandbox and execute arbitrary code. The simple filters used in practice—such as `amount > 1000 && region == 'EMEA'`—rely on comparison operators and property access, both of which remain functional under the sandbox.

## Behaviour changes

- **Expressions now operate under sandbox restrictions**: Any attempt to call a method on a class not explicitly allowed by the sandbox will be denied. JEXL sandbox denial typically results in the expression evaluating to `null` rather than throwing an exception.
- **Object instantiation is prevented**: Code like `new java.lang.Runtime()` or similar will fail silently under the sandbox.
- **Reflection-based attacks are blocked**: Calls like `getClass()`, `forName()`, or method lookups on unexpected types will not execute.
- **Context variables remain accessible**: The sandbox does not restrict access to the `amount`, `region`, `owner`, and `row` variables passed via the evaluation context, so legitimate filters continue to work.
- **No external process execution**: Even if an analyst attempts to construct a payload that worked in the unsandboxed version (e.g., Runtime.getRuntime().exec()), the sandbox prevents it from executing.

The sandbox does not change the data flow, return values, or error handling of the `applyFilter()` or `matches()` methods—only what the JEXL engine is permitted to evaluate.
