## Verdict

exploitable

## Source

User-supplied `expressionText` parameter passed from HTTP request via `RulePreviewController.preview()` at line 17, flowing to `RulePreviewService.preview()` where it becomes the argument to `parser.parseExpression(expressionText)`.

## Fix

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
        context.setRootObject(order);
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context);
    }
}
```

## Explanation

The original code uses `StandardEvaluationContext`, which permits type references (`T(java.lang.Runtime).getRuntime().exec(...)`), constructors, and bean references, making it unsafe for untrusted input. The fix replaces it with `SimpleEvaluationContext` built with `forReadOnlyDataBinding()`, which restricts evaluation to property access only and prevents method invocation and type reference attacks. The root object (`order`) is set on the restricted context, allowing legitimate property reads while blocking code execution. This eliminates the CWE-94 injection vector without changing the method's contract or return value.

## Behaviour changes

- `StandardEvaluationContext` constructor no longer called; replaced with `SimpleEvaluationContext.forReadOnlyDataBinding().build()`
- `setRootObject(order)` call added to set the evaluation root on the restricted context
- Functional behaviour preserved: expressions can still read properties from the `order` object; illegitimate expressions attempting type access or method invocation are now blocked rather than executed

