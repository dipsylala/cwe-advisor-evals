## Verdict
VULNERABLE - CWE-94 Code Injection via Spring EL Expression Language

## Source
RulePreviewController receives untrusted user input (`request.expression()`) from an HTTP request body and passes it directly to RulePreviewService.preview(), which parses and evaluates the expression without restriction, allowing arbitrary method invocation and code execution.

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
The vulnerability exists because `StandardEvaluationContext` allows arbitrary method invocation and constructor access in Spring EL expressions. This permits attackers to execute system commands via expressions like `T(java.lang.Runtime).getRuntime().exec('command')`.

The fix replaces `StandardEvaluationContext` with `SimpleEvaluationContext.forReadOnlyDataBinding()`, which:
- Disables type construction (`T()` operator)
- Disables method invocation
- Restricts evaluation to property access and built-in operators only
- Still allows reading properties from the root object (`OrderContext`)

This constrains the expression language to safe read-only operations while maintaining the required functionality of accessing order properties.
