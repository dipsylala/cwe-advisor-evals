## Verdict

Exploitable. Confidence: high.

CWE-94 (Improper Control of Generation of Code - Code Injection), location `RulePreviewService.java:14`, sink `Expression.getValue(context)` evaluated against a `StandardEvaluationContext`.

## Source

- **Source**: `RulePreviewController.preview()` deserializes the JSON request body into `RulePreviewRequest`, whose `expression()` field is attacker-controlled free text (the endpoint is `@PostMapping("/rules/preview")` with no visible authentication or authorization).
- **Flow**: `request.expression()` is passed unmodified into `RulePreviewService.preview(expressionText, order)`, parsed by `SpelExpressionParser.parseExpression(expressionText)`, and evaluated at `expression.getValue(context)` where `context` is a `new StandardEvaluationContext(order)`.
- **Sink**: `StandardEvaluationContext` permits type references, constructor calls, method invocation, and bean references in the evaluated expression - not just property access on the root object. No validation, allowlist, or sandboxing is applied to `expressionText` anywhere on this path.
- **Sink contract before the fix**: `getValue(context)` returns `Object` (the caller returns it directly as the HTTP response body); it discards nothing; the root object (`order`) is supplied implicitly via the context constructor; it throws `EvaluationException` on evaluation failure, which is not caught here (propagates as an unhandled exception / 500).

Because the standard context exposes type references and method invocation, an attacker can submit an expression such as a `T(java.lang.Runtime)` type reference to invoke arbitrary methods with the application's own privileges - full remote code execution, not merely data disclosure.

## Fix

No third-party library change is needed - `spring-expression` is already a dependency and supplies the safer context class used below.

### File: RulePreviewService.java

```java
package cases.codeinjection;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class RulePreviewService {
    private final ExpressionParser parser = new SpelExpressionParser();

    public Object preview(String expressionText, OrderContext order) {
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context, order);
    }
}
```

## Explanation

The fix replaces `StandardEvaluationContext` with `SimpleEvaluationContext.forReadOnlyDataBinding().build()`, which Spring documents as exposing property access only - no type references, constructors, method invocation, or bean references - closing the path an attacker used to reach `T(java.lang.Runtime).getRuntime().exec(...)`-style code execution. The root object is now supplied per-evaluation via `expression.getValue(context, order)` instead of baked into the context at construction time, which is the required call shape for `SimpleEvaluationContext` (it has no `setRootObject()`/constructor-root overload). This is the language guidance's named pattern for this exact sink (`SpelExpressionParser.parseExpression()` / `Expression.getValue()` against `StandardEvaluationContext`) and does not merely filter the expression text - it removes the evaluator's capability to do anything but read properties, so the fix holds regardless of how the malicious string is encoded or phrased.

## Behaviour changes

- Root object binding moved from the context constructor (`new StandardEvaluationContext(order)`) to the `getValue` call (`expression.getValue(context, order)`). Required by `SimpleEvaluationContext`'s API; property resolution on `order` (e.g. `total`, `tax`) is unchanged for read-only expressions.
- Expressions can no longer use type references (`T(...)`), constructor calls, method invocation, bean references, or assignment - only property/field reads and SpEL's built-in operators (arithmetic, comparison, ternary, elvis, etc.) against the supplied root object. Any expression that previously relied on method invocation or type references will now throw `SpelEvaluationException` instead of executing. This is the intended effect of the fix; it is flagged here because it narrows what a "rule" can express. Given the endpoint's name (`/rules/preview`) and the two-field `OrderContext(total, tax)` root object, legitimate rules are assumed to be arithmetic/comparison expressions over those fields, not method calls - if the product genuinely requires method invocation in user-authored rules, that is a separate requirement to raise, not a reason to restore `StandardEvaluationContext`.
- No change to the method signature, return type, or exception behavior on parse failure (`parser.parseExpression()` still throws `ParseException` unchanged).

**Verification**: Copied both files in the case directory to a scratch location and compiled the fixed `RulePreviewService.java` together with the unmodified `RulePreviewController.java` via `javac` against `spring-expression-6.2.16`, `spring-core-6.2.16`, and `spring-web-6.2.9` (from the local Maven repository) - compiled cleanly, no errors or warnings. Also ran the fixed code directly: `preview("total + tax", order)` returned `45` (confirming legitimate read-only property/arithmetic expressions still work), and `preview("T(java.lang.Runtime).getRuntime().exec('calc')", order)` was rejected with `org.springframework.expression.spel.SpelEvaluationException: EL1005E: Type cannot be found 'java.lang.Runtime'` (confirming the type-reference/RCE path is closed).

**Assumptions**: Assumed the preview feature's legitimate rule expressions are read-only property and arithmetic expressions over the `OrderContext` root object rather than expressions requiring method invocation, type references, or object mutation - consistent with the endpoint being a "preview" and the root object exposing only two numeric fields (`total`, `tax`).
