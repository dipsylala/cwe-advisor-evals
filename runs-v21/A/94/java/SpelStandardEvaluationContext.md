## Verdict

VULNERABLE. The application evaluates user-supplied SpEL expressions directly with `StandardEvaluationContext`, allowing arbitrary code execution.

## Source

Line 14 in `RulePreviewService.java`:

```
Expression expression = parser.parseExpression(expressionText);
return expression.getValue(context);
```

The `expressionText` parameter flows from user input via the HTTP POST endpoint in `RulePreviewController`. `StandardEvaluationContext` allows access to all bean properties, methods, type references, and constructors, enabling an attacker to execute arbitrary code through SpEL injection (e.g., expressions like `T(java.lang.Runtime).getRuntime().exec("command")`).

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
        SimpleEvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding()
            .withRootObject(order)
            .build();
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context);
    }
}
```

## Explanation

Replace `StandardEvaluationContext` with `SimpleEvaluationContext.forReadOnlyDataBinding()`. `SimpleEvaluationContext` restricts expression evaluation to property access only and blocks access to type references (`T()`), constructors, and method calls beyond a configured whitelist. This prevents SpEL injection attacks while still allowing safe property access on the root object. The `withRootObject(order)` method binds the `OrderContext` as the root object so expressions can access its properties (e.g., `total`, `tax`). Read-only binding prevents property modification through expressions.
