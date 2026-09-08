## Verdict

- **CWE:** CWE-94 (Improper Control of Generation of Code ('Code Injection'))
- **Location:** `ReportFilterService.java:38` (`jexlEngine.createExpression(filterExpression)`), executed at `ReportFilterService.java:52` (`expression.evaluate(context)`)
- **Verdict:** exploitable
- **Confidence:** high

## Source

`filterExpression`, the parameter of `ReportFilterService.applyFilter(String filterExpression, List<ReportRow> rows)`. Per the class's own javadoc, this is the raw filter text an analyst submits through the "Edit Filter" form and that is persisted unmodified on the report definition, then passed into `applyFilter` on every export run — fully attacker/analyst-controlled text with no validation or transformation applied before it reaches JEXL.

## Fix

The root cause is not the parse/evaluate calls themselves but how the `JexlEngine` is built in the constructor: `new JexlBuilder().create()` with no `JexlSandbox` and default `JexlFeatures`, so the parsed expression can reach any class or method reachable from the `JexlContext` — including `Object.getClass()` off the `row` bean, which chains into `java.lang.Class` reflection (`Class.forName`, `getMethod`, `newInstance`) capable of invoking arbitrary code such as `java.lang.Runtime.exec` or `java.lang.ProcessBuilder`.

### File: ReportFilterService.java

```java
package com.example.reporting;

import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlContext;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.JexlFeatures;
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
        // Deny-by-default sandbox: any class without an explicit entry below has
        // zero read/write/execute access, so the expression can no longer reach
        // arbitrary classes or methods (e.g. Object.getClass() -> java.lang.Class
        // -> reflection) through the "row" object in the evaluation context.
        JexlSandbox sandbox = new JexlSandbox(false);
        JexlSandbox.Permissions rowPermissions =
                sandbox.permissions(ReportRow.class.getName(), true, false, true);
        rowPermissions.read("amount", "region", "owner");
        rowPermissions.execute("getAmount", "getRegion", "getOwner");

        // The supported filter grammar is boolean/comparison expressions over
        // amount/region/owner, which need neither "new ClassName(...)" nor
        // "obj.method(...)" call syntax. Disabling both removes the reflective
        // invocation and object-construction paths at the parser level,
        // independent of what the sandbox above would otherwise allow.
        JexlFeatures features = new JexlFeatures()
                .newInstance(false)
                .methodCall(false)
                .loops(false);

        this.jexlEngine = new JexlBuilder()
                .sandbox(sandbox)
                .features(features)
                .create();
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

The original engine gave every parsed expression unrestricted access to every class and method reachable from the `JexlContext`, so an analyst-supplied filter could walk from the exposed `row` bean through `Object.getClass()` into `java.lang.Class` reflection and invoke arbitrary code, with no sandbox to stop it. The fix builds the engine with a deny-by-default `JexlSandbox` (`new JexlSandbox(false)`): any class without an explicit entry, including `java.lang.Class`, `java.lang.Runtime`, and `java.lang.ProcessBuilder`, has no read, write, or execute permission at all. `ReportRow` is given a narrow, explicit allowlist — read access to exactly the three properties the filter needs (`amount`, `region`, `owner`) and execute access to exactly their three getters — so no other member of `ReportRow`, including the inherited `getClass()`, is reachable. In parallel, `JexlFeatures.newInstance(false)` and `.methodCall(false)` remove the `new(...)` and `.method(...)` call syntax from the expression grammar entirely, at parse time, closing the object-construction and method-invocation paths regardless of what the sandbox permissions would otherwise allow. This restricts what the engine itself is capable of, rather than filtering the text of `filterExpression`, so it cannot be bypassed by rephrasing the injection — while the documented filter syntax (`amount > 1000 && region == 'EMEA'`) continues to evaluate exactly as before, since it uses only comparison/logical operators on the context variables, not method calls, object construction, or property navigation into `row`.

## Behaviour changes

- **New imports:** `org.apache.commons.jexl3.JexlFeatures` and `org.apache.commons.jexl3.introspection.JexlSandbox`. Both are part of `commons-jexl3`, the dependency already in use (`JexlBuilder`/`JexlEngine` come from the sibling package `org.apache.commons.jexl3`); confirmed against the project's resolved `commons-jexl3-3.5.0.jar` with `javap` — `JexlSandbox` lives in `org.apache.commons.jexl3.introspection` as the loaded CWE-94/java guidance states, and exposes `permissions(String, boolean, boolean, boolean)` returning a `Permissions` object with `.read(String...)` / `.execute(String...)`, matching what the fix calls.
- **Engine construction only:** the constructor now builds a `JexlSandbox` and `JexlFeatures` and passes them to `JexlBuilder.sandbox(...)`/`.features(...)` before `.create()`. This is the security control itself, not incidental scope creep — `applyFilter`, `matches`, `ReportRow`, and the values placed in the `JexlContext` are all unchanged.
- **Failure behaviour for rejected expressions:** previously a reflective or constructing expression simply executed. Now such an expression throws an unchecked `org.apache.commons.jexl3.JexlException` — `JexlException.Feature` at parse time (`createExpression`) for disabled grammar constructs (`new(...)`, `.method(...)`), or `JexlException.Property`/`Method` at evaluate time (`expression.evaluate(context)`) for a sandbox-denied member. `applyFilter` does not catch this and it propagates out of the stream's `filter()` lambda, same as `createExpression` already does today for a syntactically invalid filter string — callers of this method already have to tolerate a `JexlException` from it.
- **Assumption:** the filter grammar the application actually needs is limited to comparison/logical operators over `amount`/`region`/`owner` — the only form shown in the class's own javadoc and the only one exercised by `matches()`. If saved filters legitimately call String/Number methods (e.g. `region.toLowerCase()`) or navigate from `row` into other members, those expressions will now be rejected; widening support means adding named entries to the sandbox allowlist deliberately, not reverting to an unrestricted engine.
- **Verification:** compiled the modified file with `javac` against the project's resolved `commons-jexl3-3.5.0.jar` on a local JDK — clean compile, no errors or warnings. Also ran it (`java`, same classpath plus `commons-logging`, which `commons-jexl3` requires at runtime) with a harness covering: (1) the documented filter, `amount > 1000 && region == 'EMEA'`, evaluates and returns the correct row set, confirming the fix preserves the intended feature; (2) `owner.getClass().forName('java.lang.Runtime')...` and `row.class.forName(...)`-style reflection attempts are rejected — the method-call form fails to parse (`Feature: method call error in '.getClass(...)'` / `'.forName(...)'`) because `methodCall` is disabled, and the bare property form (`row.class`, `owner.class`, `amount.class`) is rejected by the sandbox's deny-by-default policy (`Property: undefined property 'class'`), confirmed by contrast against the identical probe run on a plain unsandboxed engine, which resolves `row.class` to the actual `Class` object; (3) `new('java.lang.ProcessBuilder', [...])` fails to parse (`Feature: create instance error in 'new(...)'`) because `newInstance` is disabled. All three checks matched the intended sandboxed behaviour, and the sandbox's `read`/`execute` permission values for `ReportRow` were also checked directly (`sandbox.read(ReportRow.class, "amount")` → `"amount"`; `sandbox.read(ReportRow.class, "class")` → `null`; `sandbox.execute(ReportRow.class, "getClass")` → `null`), matching the intended allow/deny set exactly.
- **Unrelated observation, not a fix defect:** on the JDK used for this verification, direct bean-style navigation of the form `row.amount` failed to resolve a value even against a completely unmodified, unsandboxed baseline engine with no security changes applied — a pre-existing JEXL/JDK interaction independent of this fix. The application's documented filter syntax reads through the flat `amount`/`region`/`owner` context variables, not through `row.<property>` navigation, so this does not affect the correctness of the fix.
