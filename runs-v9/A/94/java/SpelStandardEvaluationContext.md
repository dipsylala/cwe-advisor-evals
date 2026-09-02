## Verdict

Confirmed. `RulePreviewService.preview()` parses an attacker-controlled string (`RulePreviewRequest.expression()`, taken directly from an unauthenticated `@RequestBody` in `RulePreviewController`) as a Spring Expression Language (SpEL) expression and evaluates it against a `StandardEvaluationContext`. `StandardEvaluationContext` allows the full SpEL feature set - type references (`T(...)`), constructor invocation (`new ...`), static method calls, and arbitrary reflective method invocation on any reachable object. A request body such as `{"expression": "T(java.lang.Runtime).getRuntime().exec(\"calc\")"}` (or the classic `T(java.lang.ProcessBuilder)`-based chain) is evaluated with the privileges of the host process, giving remote code execution, not just data access on `OrderContext`.

## Source

`request.expression()` in `RulePreviewController.preview()` (`RulePreviewController.java:16-17`), passed unmodified into `RulePreviewService.preview(String expressionText, OrderContext order)` and on into `parser.parseExpression(expressionText)` / `expression.getValue(context)` at `RulePreviewService.java:13-14`. The sink is the combination of `SpelExpressionParser.parseExpression()` on this untrusted string plus evaluation against a `StandardEvaluationContext`.

## Fix

```java
package cases.codeinjection;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class RulePreviewService {
    private final ExpressionParser parser = new SpelExpressionParser();

    public Object preview(String expressionText, OrderContext order) {
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Expression expression = parser.parseExpression(expressionText);
        return expression.getValue(context, order);
    }
}
```

The controller does not need to change; the fix is entirely inside the evaluation context construction.

## Explanation

`StandardEvaluationContext` is the "everything enabled" SpEL context: it wires in reflective property/method resolvers, a constructor resolver, and a type locator, so any expression string can reach arbitrary classes on the classpath (`T(...)`), instantiate them (`new ...`), and invoke arbitrary public methods (`.getRuntime().exec(...)`, `.getClass().forName(...)`, etc.). That is appropriate only when the expression text itself is trusted (e.g., authored by developers in config), never when it originates from a request body.

`SimpleEvaluationContext` is Spring's documented, purpose-built context for evaluating expressions from external/untrusted sources. `forReadOnlyDataBinding().build()` configures it with only a data-binding property accessor for reading properties off the supplied root object graph - it registers no type locator, no constructor resolver, and (unless `.withInstanceMethods()` is explicitly added) no method resolver, so `T()`, `new`, and arbitrary method invocation all fail to resolve at evaluation time instead of executing. The root object is passed via the two-argument `expression.getValue(context, order)` overload so property expressions like `total > 100` (mapping to `OrderContext.total()`/its accessor) continue to work for legitimate "preview a rule" use cases, while the expression string can no longer escape the `OrderContext` property surface.

Do not add `.withInstanceMethods()` to the builder for this use case: that re-enables reflective method invocation on whatever the root object and its properties expose, which can reopen a path to dangerous methods if `OrderContext` (or a future root type) ever gains one. If a rule genuinely needs to call methods rather than just read properties, prefer exposing a narrow, purpose-built set of functions/variables registered explicitly on the `SimpleEvaluationContext` rather than falling back to `StandardEvaluationContext` or blanket instance-method access.

After the fix, verify that a benign rule expression such as `total > 100` still evaluates correctly against `OrderContext`, and that a payload like `T(java.lang.Runtime).getRuntime().exec('id')` or `new java.lang.ProcessBuilder('id').start()` now throws a `SpelEvaluationException` (type/constructor not found) instead of executing.
