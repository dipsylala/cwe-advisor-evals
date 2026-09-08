## Verdict

Confirmed. `ReportFilterService` builds its `JexlEngine` with `new JexlBuilder().create()` and no `JexlSandbox`/permissions configured, then compiles and evaluates an analyst-supplied string as a JEXL expression. Apache Commons JEXL supports calling arbitrary reachable methods and constructors (for example `something.getClass().forName('java.lang.Runtime').getMethod('exec', ...)`-style gadget chains, or direct construction of classes like `java.lang.ProcessBuilder`) unless the engine's permissions restrict it. An analyst able to edit the saved filter text can therefore execute arbitrary Java on the server - this is CWE-94.

## Source

- Origin: `filterExpression` parameter of `ReportFilterService.applyFilter(String, List<ReportRow>)`. Per the class javadoc it is "the raw filter text ... originally submitted by the analyst through the 'Edit Filter' form and persisted unmodified" - attacker-influenced, persisted, untrusted data.
- Flow: `applyFilter` passes `filterExpression` straight into `jexlEngine.createExpression(filterExpression)` (line 38) with no validation or transformation.
- Sink: `expression.evaluate(context)` in `matches(...)` (line 52) executes the compiled expression against a `JexlContext`. Because the engine was built with no sandbox, the expression can reach any class/method/constructor visible on the classpath, not just the four bindings (`amount`, `region`, `owner`, `row`) placed in the context.

## Fix

### File: ReportFilterService.java
```java
package com.example.reporting;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.introspection.JexlSandbox;

import java.util.List;

/**
 * Applies a user-authored filter expression to a report's row data.
 *
 * Analysts can save a custom filter (e.g. "amount > 1000 &amp;&amp; region == 'EMEA'")
 * on the report definition. This service evaluates that expression against
 * each row before the row is included in the exported report.
 */
public class ReportFilterService {

    private final JexlEngine jexlEngine;

    public ReportFilterService() {
        // The engine is built with a JexlSandbox that leaves normal use of the
        // row data alone (arithmetic and string comparisons, calls on
        // ReportRow's own getters) but explicitly blocks the JDK classes an
        // analyst-authored expression could otherwise reach to escape the
        // expression sandbox: reflection, class/classloader access, process
        // and system access, and filesystem/network I/O. The block list is
        // applied explicitly here rather than relied on as an engine default,
        // because JexlBuilder's built-in default permissions differ across
        // commons-jexl3 releases (unrestricted through the 3.2 line,
        // progressively tightened from 3.3 onward), so the protection must
        // not depend on which release happens to be on the classpath.
        this.jexlEngine = new JexlBuilder().sandbox(createSandbox()).create();
    }

    private static JexlSandbox createSandbox() {
        // Allow-by-default sandbox: every class stays usable unless it is
        // explicitly blocked below (an allow-list here would also have to
        // enumerate every legitimate type an analyst filter might touch,
        // such as String and Number, and would keep breaking as filters
        // evolve).
        JexlSandbox sandbox = new JexlSandbox();

        // Reflection and class/classloader access - the standard gadget
        // chain ("obj.getClass().forName(...)...", "obj.getClass().getMethod(...)")
        // used to reach arbitrary classes from inside a sandboxed expression.
        sandbox.block("java.lang.Class");
        sandbox.block("java.lang.ClassLoader");
        sandbox.block("java.lang.reflect.Method");
        sandbox.block("java.lang.reflect.Constructor");
        sandbox.block("java.lang.reflect.Field");
        sandbox.block("java.lang.reflect.AccessibleObject");
        sandbox.block("java.lang.reflect.Proxy");
        sandbox.block("java.lang.invoke.MethodHandles");

        // Process and system access.
        sandbox.block("java.lang.Runtime");
        sandbox.block("java.lang.Process");
        sandbox.block("java.lang.ProcessBuilder");
        sandbox.block("java.lang.System");

        // Filesystem access.
        sandbox.block("java.io.File");
        sandbox.block("java.io.FileInputStream");
        sandbox.block("java.io.FileOutputStream");
        sandbox.block("java.io.FileReader");
        sandbox.block("java.io.FileWriter");
        sandbox.block("java.io.RandomAccessFile");
        sandbox.block("java.nio.file.Files");
        sandbox.block("java.nio.file.Paths");

        // Network access (SSRF / data exfiltration).
        sandbox.block("java.net.URL");
        sandbox.block("java.net.URLClassLoader");
        sandbox.block("java.net.Socket");
        sandbox.block("java.net.InetAddress");

        return sandbox;
    }

    /**
     * Returns only the rows whose data satisfies the analyst-supplied filter.
     *
     * @param filterExpression the raw filter text saved on the report definition,
     *                         originally submitted by the analyst through the
     *                         "Edit Filter" form and persisted unmodified.
     * @param rows             the report's data rows for the current run.
     */
    public List<ReportRow> applyFilter(String filterExpression, List<ReportRow> rows) {
        JexlExpression expression = jexlEngine.createExpression(filterExpression);

        return rows.stream()
                .filter(row -> matches(expression, row))
                .toList();
    }

    private boolean matches(JexlExpression expression, ReportRow row) {
        JexlContext context = new MapContext();
        context.set("amount", row.getAmount());
        context.set("region", row.getRegion());
        context.set("owner", row.getOwner());
        context.set("row", row);

        Object result = expression.evaluate(context);
        return Boolean.TRUE.equals(result);
    }

    public static class ReportRow {
        private final double amount;
        private final String region;
        private final String owner;

        public ReportRow(double amount, String region, String owner) {
            this.amount = amount;
            this.region = region;
            this.owner = owner;
        }

        public double getAmount() {
            return amount;
        }

        public String getRegion() {
            return region;
        }

        public String getOwner() {
            return owner;
        }
    }
}
```

## Explanation

The root cause is not the choice of JEXL as an expression engine but the engine's permission configuration: with no `JexlSandbox` (or restricted `JexlPermissions`) applied, a compiled `JexlExpression` can invoke any public constructor or method reachable from the bindings in its `JexlContext`, including static entry points like `Class.forName`, `Runtime.getRuntime().exec(...)`, or `new('java.lang.ProcessBuilder', ...)`. Because `filterExpression` is analyst-controlled and persisted, this is a direct path from stored input to arbitrary code execution, not just to the intended row-filtering logic.

The fix keeps the JEXL-based filtering feature - rewriting it as a bespoke parser would be a disproportionate change for a "compare a few fields" use case - and instead constrains what the compiled expression can reach. `JexlSandbox` is configured as allow-by-default and then explicitly blocks the specific JDK classes that provide reflection, class/classloader access, process/system access, and filesystem/network I/O. This targets exactly the classes an expression would need to escape its intended scope, while leaving every other class - including `String`, the boxed numeric types, and `ReportRow` itself - fully usable, so existing and future analyst filters that compare `amount`, `region`, or `owner`, or call `ReportRow`'s own getters, continue to work unchanged.

An allow-list sandbox (block everything except a fixed list of "safe" classes) was considered and rejected: it would have to anticipate every type a legitimate filter might use and would silently reject valid analyst expressions as JEXL usage evolves, which is a functional regression rather than a security improvement. The block-list above is also applied explicitly via `JexlSandbox` rather than by relying on `JexlBuilder`'s implicit default, because that default's strictness has changed across commons-jexl3 releases; explicit configuration keeps the protection stable regardless of which release is on the classpath.
