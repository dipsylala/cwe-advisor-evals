## Verdict

VULNERABLE - Fixed.

## Source

Untrusted user input flows from HTTP POST body parameter `expression` in `RulePreviewController` to the SpEL parser.

Call chain: `RulePreviewController.preview()` (line 16-17) → `RulePreviewService.preview()` (line 11-15) → `expression.getValue(context)` (line 14).

## Fix

Replace `StandardEvaluationContext` with `SimpleEvaluationContext.forReadOnlyDataBinding().build()` and pass the root object to `getValue()`.

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

The vulnerability arose from using `StandardEvaluationContext`, which permits type references (`T(java.lang.Runtime).getRuntime().exec(...)`), constructors, and unrestricted method invocation. An attacker supplying a malicious expression string could execute arbitrary code with full access to the runtime.

The fix replaces `StandardEvaluationContext` with `SimpleEvaluationContext.forReadOnlyDataBinding().build()`, which:

- Restricts evaluation to read-only property access on the root object only
- Disallows type references and the `T()` function
- Disallows constructors and bean references
- Denies method invocation beyond property getters

The root object (the `order` parameter) is passed to `getValue(context, order)` as the context data, allowing legitimate property reads like `total` or `tax` while blocking dangerous operations.

## Behaviour changes

The evaluation context is now restricted to read-only property access on the `OrderContext` object. Expressions that previously worked via type references, method calls, or constructors will no longer be evaluated:

- `T(java.lang.Runtime).getRuntime().exec(...)` → no longer evaluates; returns `null`
- `order.getClass()` → no longer evaluates; returns `null`
- `new java.lang.String(...)` → no longer evaluates; returns `null`

Legitimate property reads like `total` and `tax` remain functional and evaluate correctly.

Application code that relied on method invocation or type references in stored expressions would need to be refactored to use a lookup table or strategy pattern instead. If the application currently allows such expressions, this is an intentional breaking change to eliminate code injection risk.
