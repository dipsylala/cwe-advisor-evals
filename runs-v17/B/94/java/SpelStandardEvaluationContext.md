## Verdict

Exploitable. Untrusted user input from an HTTP POST request is evaluated as Spring Expression Language (SpEL) code using `StandardEvaluationContext`, which permits type references, method invocation, and constructor calls. An attacker can submit a request with an expression like `T(java.lang.Runtime).getRuntime().exec("malicious-command")` to achieve remote code execution.

## Source

HTTP POST request body: `RulePreviewController.preview(@RequestBody RulePreviewRequest request)` receives the expression string via `request.expression()`. The RulePreviewRequest record contains an untrusted `String expression` field that comes directly from the request JSON.

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
        SimpleEvaluationContext context = SimpleEvaluationContext.forPropertyAccessors().build();
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context, order);
    }
}
```

## Explanation

The fix replaces `StandardEvaluationContext` with `SimpleEvaluationContext.forPropertyAccessors()`, which restricts SpEL evaluation to read-only property access on objects. This eliminates the ability to use type references (`T(...)` expressions), constructor invocation, and method calls. The root object (`order`) is now passed as a parameter to `getValue(context, order)` instead of being bound to the evaluation context at construction. With `SimpleEvaluationContext`, attackers can still evaluate expressions like `order.total`, but cannot access Java reflection APIs, execute arbitrary methods, or instantiate classes. This closes the code injection vector while preserving the legitimate use case of property-based expression evaluation.

## Behaviour changes

The evaluation now passes the root object as a separate parameter to `getValue()` rather than embedding it in the context. The method signature changes from `expression.getValue(context)` to `expression.getValue(context, order)`. This is a required change to use `SimpleEvaluationContext` correctly and does not alter the return value or observable behavior for legitimate property-access expressions. Expressions that previously leveraged type references or method invocation will now fail to parse or evaluate, which is the intended security hardening.
