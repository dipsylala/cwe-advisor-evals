## Verdict

- **CWE**: CWE-94 (Improper Control of Generation of Code / Code Injection)
- **Verdict**: exploitable
- **Confidence**: high
- **Location**: `RulePreviewService.java`, line 14 (sink), reached from line 13's `parseExpression` call

## Source

`RulePreviewController.preview()` deserializes the HTTP request body into `RulePreviewRequest` and passes `request.expression()` - an attacker-controlled string with no validation, length limit, or character restriction anywhere in the chain - straight into `RulePreviewService.preview(expressionText, order)`.

## Fix

**Library recommendation**: Apache Commons JEXL (`org.apache.commons:commons-jexl3`) as the sandboxed replacement for SpEL. The loaded guidance does not carry a minimum safe version for this library; confirm the current release against SCA/dependency-check tooling before adding it to `pom.xml` / `build.gradle`, rather than trusting a version supplied here.

Vulnerable code (`RulePreviewService.java`):

```java
package cases.codeinjection;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

public class RulePreviewService {
    private final ExpressionParser parser = new SpelExpressionParser();

    public Object preview(String expressionText, OrderContext order) {
        StandardEvaluationContext context = new StandardEvaluationContext(order);
        Expression expression = parser.parseExpression(expressionText);
        // SINK: expressionText is attacker-controlled (HTTP request body) and is
        // evaluated against a StandardEvaluationContext, which permits type
        // references, constructors, and arbitrary method invocation - e.g.
        // T(java.lang.Runtime).getRuntime().exec("...") - full code execution.
        return expression.getValue(context);
    }
}
```

Fixed code:

```java
package cases.codeinjection;

import java.util.regex.Pattern;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.introspection.JexlSandbox;

public class RulePreviewService {
    // Deny-by-default sandbox: no Java class is exposed to the expression at
    // all, so there is nothing for the sandbox to explicitly allow. Object
    // construction is blocked as a separate control, per the JEXL guidance.
    private static final JexlSandbox SANDBOX = new JexlSandbox(false);

    // Rule expressions are short arithmetic/comparison formulas over the
    // order totals; this allowlist is defence-in-depth on top of the
    // sandbox, not the primary control.
    private static final Pattern ALLOWED_EXPRESSION =
            Pattern.compile("^[\\w\\s+\\-*/%()<>=!&|.,]{1,200}$");

    private final JexlEngine engine = new JexlBuilder()
            .sandbox(SANDBOX)
            .features(new org.apache.commons.jexl3.JexlFeatures().newInstance(false))
            .build();

    public Object preview(String expressionText, OrderContext order) {
        if (expressionText == null || !ALLOWED_EXPRESSION.matcher(expressionText).matches()) {
            throw new IllegalArgumentException("Invalid rule expression");
        }
        // Only the two primitive values the rule is meant to operate on are
        // exposed as variables - never the OrderContext object itself - so
        // there is no bean, class, or method reference for an injected
        // expression to reach into.
        MapContext context = new MapContext();
        context.set("total", order.total());
        context.set("tax", order.tax());
        JexlExpression expression = engine.createExpression(expressionText);
        return expression.evaluate(context);
    }
}
```

## Explanation

The vulnerability is that `expressionText` comes straight from the HTTP request body and is evaluated with Spring's `StandardEvaluationContext`, which resolves type references, constructors, and method invocation on the bound root object - so a request body like `T(java.lang.Runtime).getRuntime().exec("id")` executes arbitrary code with the application's own privileges. The knowledge base is explicit that SpEL is not the evaluator to reach for untrusted input even via `SimpleEvaluationContext`, since Spring itself documents that restriction as best-effort and states that evaluating an expression from an untrusted source is inherently dangerous regardless of context. The fix replaces SpEL with Apache Commons JEXL configured deny-by-default (`new JexlSandbox(false)`, `JexlFeatures.newInstance(false)`) so no Java class, constructor, or method is reachable from the expression at all; the `MapContext` exposes only the two primitive values (`total`, `tax`) the feature needs, never the `OrderContext` object itself, closing off bean/property navigation as an attack surface. A narrow character allowlist is layered on top as defence-in-depth, consistent with the root guidance's instruction to treat validation as secondary to isolation, not a replacement for it.

## Behaviour changes

- **Evaluator and syntax swapped**: expressions now run through JEXL instead of SpEL. Any expression that relied on SpEL-specific syntax (type references, ternary operators, method calls, bean navigation into `order`) will now fail to parse or evaluate; only arithmetic/comparison expressions referencing the bare names `total` and `tax` are supported. This narrowing is the intended effect of the fix, not an incidental change.
- **New input validation added**: expressions are now checked against a character/length allowlist before evaluation and rejected with `IllegalArgumentException` if they don't match. The original code had no such check. This is a new fail-closed behaviour, added as defence-in-depth per the guidance, and will reject previously-accepted expressions that use characters outside the allowlist (e.g. quotes, brackets).
- **Context content changed**: the evaluation context previously exposed the full `OrderContext` object as the SpEL root (implicitly reachable via bean-style property/method resolution); it now exposes only the two primitive fields as named variables. Any expression that depended on additional `OrderContext` members beyond `total`/`tax`, or on reflective/bean-style access, is no longer supported - none currently exist on the record, so no legitimate current usage is affected.
- **Return value and type**: unchanged - both `expression.getValue(context)` and `expression.evaluate(context)` return `Object`, and the method signature is untouched.
- **Failure behaviour**: parse/evaluation errors previously surfaced as an unchecked Spring `EvaluationException`; they now surface as an unchecked JEXL `JexlException`. Both are unchecked runtime exceptions, so no caller needs a new catch clause, but callers pattern-matching on the specific exception type would need updating - none exist in this call chain.
