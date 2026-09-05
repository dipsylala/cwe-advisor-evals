## Verdict

VULNERABLE - CWE-94 code injection through Spring Expression Language. User-supplied expression text is directly evaluated with `StandardEvaluationContext`, which permits type references (`T(java.lang.Runtime)`), method invocation, and object construction. An attacker can execute arbitrary code within the application's JVM.

## Source

**File:** RulePreviewService.java
**Line:** 14

The vulnerability path flows from the web controller through the service:
- `RulePreviewController.preview()` receives user input `request.expression()` from a POST request body (line 16 of RulePreviewController.java)
- This untrusted string is passed to `RulePreviewService.preview(String expressionText, OrderContext order)` (line 12)
- The service parses and evaluates the expression with `parser.parseExpression(expressionText)` (line 13, sink)
- Then evaluates it against `StandardEvaluationContext` with `expression.getValue(context)` (line 14, sink)

`StandardEvaluationContext` is unrestricted: it allows type references, method calls, and object instantiation, enabling payloads like `T(java.lang.Runtime).getRuntime().exec("malicious command")`.

## Fix

Replace `StandardEvaluationContext` with `SimpleEvaluationContext`:

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

The fix replaces `StandardEvaluationContext` with `SimpleEvaluationContext.forReadOnlyDataBinding()`. This restricts expression evaluation to read-only property access on the context's root object, removing access to:
- Type references (`T(java.lang.Runtime)`)
- Method invocation
- Object constructors
- Bean references

`SimpleEvaluationContext` is designed for user-supplied expressions where only data access is needed. It prevents arbitrary code execution while preserving the ability to evaluate property-access expressions like `order.total` or `order.tax` against the provided `OrderContext` object.

The original intent—previewing calculation rules over an order object—is preserved; the dangerous capability is gone.

## Behaviour changes

**Expressions that now fail:**
- `T(java.lang.Runtime).getRuntime().exec("command")` → blocked
- `java.lang.Runtime.getRuntime()` → blocked
- `new java.io.File("/etc/passwd")` → blocked
- Method calls: `@someBean.methodName()` → blocked

**Expressions that still work:**
- `total` (property access on root object)
- `tax` (property access on root object)
- Property navigation: `order.total` (if order were a property)
- Arithmetic: `total + tax`
- Conditionals: `total > 100 ? 'high' : 'low'`

The evaluation context is now read-only; if the application needs to execute expressions that require side effects or method calls, those cannot be satisfied by `SimpleEvaluationContext` and the application architecture must be reconsidered to avoid dynamic expression evaluation altogether (e.g., use a lookup table or strategy pattern instead).
