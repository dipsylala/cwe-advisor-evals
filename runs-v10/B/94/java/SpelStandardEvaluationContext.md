## Verdict

Exploitable. Untrusted user input from an HTTP POST request is evaluated as a Spring Expression Language expression using `StandardEvaluationContext`, which permits type references and method invocation. An attacker can inject expressions like `T(java.lang.Runtime).getRuntime().exec("command")` to execute arbitrary code with the application's privileges.

## Source

`RulePreviewController.preview()` receives `request.expression()` from an HTTP POST request body. The expression field is user-controlled and untrusted. The expression is passed to `RulePreviewService.preview(String expressionText, OrderContext order)` at line 17 of RulePreviewController.

## Fix

Vulnerable code (RulePreviewService.java, lines 11-15):
```java
public Object preview(String expressionText, OrderContext order) {
    StandardEvaluationContext context = new StandardEvaluationContext(order);
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

Fixed code:
```java
public Object preview(String expressionText, OrderContext order) {
    SimpleEvaluationContext context = SimpleEvaluationContext
        .forPropertyAccessors(order)
        .build();
    Expression expression = parser.parseExpression(expressionText);
    return expression.getValue(context);
}
```

Required import addition:
```java
import org.springframework.expression.spel.support.SimpleEvaluationContext;
```

(Remove the import of `StandardEvaluationContext` if it is no longer used elsewhere in the class.)

## Explanation

The fix replaces `StandardEvaluationContext` with `SimpleEvaluationContext.forPropertyAccessors()`, which restricts expression evaluation to property access only. `SimpleEvaluationContext` does not permit type references, method invocation, constructors, or bean references—the mechanisms an attacker would use to execute arbitrary code. The context still wraps the `OrderContext` object and allows the expression to read its properties, preserving the intended functionality while eliminating the injection vector.

## Behaviour changes

None. The `forPropertyAccessors(Object)` method takes the same root object as `StandardEvaluationContext` and returns the same evaluation results for legitimate property-access expressions. An expression that previously worked with `StandardEvaluationContext` (e.g., accessing `order.total` or `order.tax`) continues to work with `SimpleEvaluationContext`. Expressions that attempt dangerous operations (type references, method calls, object construction) are now blocked and return null or raise an exception, depending on the expression parser's configuration. This is the intended behavior change—rejecting expressions that could exploit the application.
